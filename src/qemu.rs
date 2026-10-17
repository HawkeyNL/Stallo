//! The QEMU command line and the per-VM disk files.
//!
//! `argv` is a pure function so the full command line is pinned by a golden
//! test: one machine type, a fixed device set, no defaults, seccomp sandbox,
//! and no network device unless a profile adds one.

use std::os::fd::RawFd;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use tokio::process::Command;

use crate::config::{NetProfile, VmConfig};
use crate::images::{Agent, Firmware, Os};
use crate::run_tool;

pub const QEMU: &str = "/usr/bin/qemu-system-x86_64";
/// Secure Boot capable firmware for every VM. The variable store decides
/// whether Secure Boot is on: with Microsoft's keys enrolled it is (Ubuntu's
/// and Fedora's shims are signed by Microsoft); with no keys enrolled the
/// firmware stays in setup mode and boots anything (`uefi` images). SMM and
/// the secure flash are the same either way.
pub const OVMF_CODE: &str = "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd";
pub const OVMF_VARS: &str = "/usr/share/OVMF/OVMF_VARS_4M.ms.fd";
pub const OVMF_VARS_NO_KEYS: &str = "/usr/share/OVMF/OVMF_VARS_4M.fd";

/// Guest screen size; screenshots and pointer coordinates use it 1:1.
pub const SCREEN: (u32, u32) = (1280, 800);

/// File names inside the VM directory and the VM runtime directory.
pub const DISK: &str = "disk.qcow2";
pub const VARS: &str = "vars.qcow2";
pub const SEED: &str = "seed.iso";
/// Directory with one image per RAM snapshot (see `snapshot.rs`).
pub const STATES: &str = "states";
pub const QMP_SOCK: &str = "qmp.sock";
pub const QGA_SOCK: &str = "qga.sock";
pub const VNC_SOCK: &str = "vnc.sock";
/// Screendumps; created by the daemon, written by QEMU.
pub const SCREEN_FILES: [&str; 2] = ["screen.png", "screen.ppm"];

const WAIT_ONLINE: &str = "systemd-networkd-wait-online.service";
/// Waits for NTP before `time-sync.target`, with no timeout. Arch enables
/// it, and its first boot orders cloud-init's final stage (and so the guest
/// agent) after that target. Masked for every profile: the guest clock
/// comes from the host, and NTP may be blocked or slow even with a network.
const TIME_WAIT_SYNC: &str = "systemd-time-wait-sync.service";

/// A drop-in for a preinstalled guest agent: it starts only after
/// cloud-init's final stage. Otherwise it answers seconds before the seed
/// has created the guest user and run its commands (seed.rs), and "ready"
/// would come too early. Never for an agent the seed installs: its
/// `systemctl start` inside the final stage would wait for itself.
const QGA_AFTER_CLOUD_INIT: &str = "[Unit]\nAfter=cloud-final.service\n";

/// The machine type is pinned rather than the moving `q35` alias, so a QEMU
/// upgrade does not silently change the virtual hardware under saved VM
/// state. Ubuntu 26.04 ships QEMU 10.2.
pub const MACHINE: &str = "pc-q35-10.2";

/// Hyper-V enlightenments for Windows guests: paravirtual timers, clocks,
/// TLB flushes and IPIs. `hv-stimer` replaces the HPET (`hpet=off`).
const HYPERV: &str = "hv-relaxed,hv-vapic,hv-spinlocks=0x1fff,hv-vpindex,hv-runtime,hv-synic,hv-stimer,hv-time,hv-frequencies,hv-tlbflush,hv-ipi";

/// The second drive of a VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Media<'a> {
    /// The seed ISO (cloud images), as a virtio disk.
    Seed,
    /// A CD-ROM drive (installer ISOs) with this ISO, or empty. The drive is
    /// there either way, so the virtual hardware stays the same when the
    /// ISO is ejected.
    Cdrom(Option<&'a Path>),
}

/// Builds the QEMU argv (without the program) for `vm`. `net_fd` is QEMU's
/// end of the passt socketpair: required for the `internet` profile, and
/// refused for `offline`. `vnc` is the VNC socket: required when `vm.vnc`
/// is on, and refused otherwise. `agent` is how the image gets its guest
/// agent.
///
/// `vm.machine` picks the hardware. A Windows VM (always from an ISO) gets
/// devices Windows has drivers for out of the box: an AHCI disk, an e1000e
/// NIC and a USB tablet instead of virtio ones, plus Hyper-V
/// enlightenments and an RTC in local time.
pub fn argv(
    vm: &VmConfig,
    vm_dir: &Path,
    rt_dir: &Path,
    net_fd: Option<RawFd>,
    vnc: Option<&Path>,
    agent: Agent,
    media: Media,
) -> Result<Vec<String>> {
    // Names and uuids end up inside option strings; never trust the caller.
    vm.validate()?;
    let windows = vm.machine == Os::Windows;
    ensure!(!windows || media != Media::Seed, "a Windows VM has no seed");
    ensure!(
        vm.vnc == vnc.is_some(),
        "vnc {} with socket {vnc:?}",
        vm.vnc
    );
    // A Unix socket only: VNC has no usable authentication.
    let vnc = vnc
        .map(|p| Ok::<_, anyhow::Error>(format!("-vnc unix:{}", opt_path(p)?)))
        .transpose()?;
    // The SMBIOS systemd credentials below tune the boot of the cloud
    // guests Stallo sets up. A guest installed from an ISO is the user's
    // own system: it gets none.
    let managed = media == Media::Seed;
    // systemd >= 256 reads `systemd.unit-dropin.*` credentials. Base64
    // has no spaces or commas.
    let qga_order = (managed && agent == Agent::Preinstalled).then(|| {
        format!(
            "-smbios type=11,value=io.systemd.credential.binary:systemd.unit-dropin.qemu-guest-agent.service={}",
            BASE64.encode(QGA_AFTER_CLOUD_INIT)
        )
    });
    let network = match (vm.net, net_fd) {
        // No NIC means no link ever comes online, and Ubuntu's boot then
        // waits 2 minutes for systemd-networkd-wait-online. An empty
        // `systemd.extra-unit.*` credential masks a unit (systemd >= 256;
        // for older systemd see the offline network-config in seed.rs).
        (NetProfile::Offline, None) => ["-nic none".to_owned()]
            .into_iter()
            .chain(managed.then(|| {
                format!(
                    "-smbios type=11,value=io.systemd.credential:systemd.extra-unit.{WAIT_ONLINE}="
                )
            }))
            .collect(),
        // An already connected socket (see net.rs). `romfile=`: no iPXE
        // option ROM, so no network boot code in the firmware. e1000e is
        // more emulated code for the guest to reach than virtio-net; the
        // QEMU confinement (confine.rs, AppArmor) is what contains it.
        (NetProfile::Internet, Some(fd)) => vec![
            format!("-netdev stream,id=net0,server=off,addr.type=fd,addr.str={fd}"),
            format!(
                "-device {},netdev=net0,mac={},romfile=",
                if windows { "e1000e" } else { "virtio-net-pci" },
                crate::net::mac(vm)
            ),
        ],
        (net, fd) => bail!("network profile {net:?} with passt socket {fd:?}"),
    };
    let time_sync = managed.then(|| {
        format!("-smbios type=11,value=io.systemd.credential:systemd.extra-unit.{TIME_WAIT_SYNC}=")
    });
    let file = |dir: &Path, name: &str| opt_path(&dir.join(name));
    let (disk, vars) = (file(vm_dir, DISK)?, file(vm_dir, VARS)?);
    // The disk boots first; a blank one falls through to the CD-ROM. The
    // ISO's format is pinned (raw), so QEMU never probes it.
    let media = match media {
        Media::Seed => vec![
            format!(
                "-blockdev driver=file,node-name=seed,filename={},read-only=on",
                file(vm_dir, SEED)?
            ),
            "-device virtio-blk-pci,drive=seed".to_owned(),
        ],
        Media::Cdrom(Some(iso)) => vec![
            format!(
                "-blockdev driver=file,node-name=cd0-file,filename={},read-only=on",
                opt_path(iso)?
            ),
            "-blockdev driver=raw,node-name=cd0,file=cd0-file,read-only=on".to_owned(),
            "-device ide-cd,id=cd0,drive=cd0,bus=ide.0,bootindex=2".to_owned(),
        ],
        Media::Cdrom(None) => vec!["-device ide-cd,id=cd0,bus=ide.0,bootindex=2".to_owned()],
    };
    let (qmp, qga) = (file(rt_dir, QMP_SOCK)?, file(rt_dir, QGA_SOCK)?);
    let (name, uuid) = (&vm.name, &vm.uuid);
    let (w, h) = SCREEN;
    let (hpet, hyperv, disk_dev, pointer) = if windows {
        (
            ",hpet=off",
            format!(",{HYPERV}"),
            "ide-hd,drive=disk0,bus=ide.1",
            "-device qemu-xhci,id=usb -device usb-tablet,bus=usb.0",
        )
    } else {
        (
            "",
            String::new(),
            "virtio-blk-pci,drive=disk0",
            "-device virtio-tablet-pci",
        )
    };
    // Windows keeps the RTC in local time.
    let rtc = windows.then(|| "-rtc base=localtime,driftfix=slew".to_owned());

    let args = [
        format!("-name guest={name},debug-threads=on"),
        format!("-uuid {uuid}"),
        "-nodefaults -no-user-config -display none -msg timestamp=on".into(),
        "-sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny".into(),
        // mem-merge=off: no KSM page sharing between guests and the host
        // (side channels). vmport=off: no VMware backdoor port.
        format!(
            "-machine {MACHINE},accel=kvm,smm=on,dump-guest-core=off,mem-merge=off,vmport=off,pflash0=fw-code,pflash1=fw-vars{hpet}"
        ),
        "-global driver=cfi.pflash01,property=secure,value=on".into(),
        // Guests cannot suspend or hibernate and wedge automation.
        "-global ICH9-LPC.disable_s3=1 -global ICH9-LPC.disable_s4=1".into(),
        // No nested virtualisation: it exposes KVM's nested code to the guest.
        format!(
            "-cpu host,-svm,-vmx{hyperv} -smp {} -m {}",
            vm.vcpus, vm.memory_mib
        ),
        format!("-blockdev driver=file,node-name=fw-code,filename={OVMF_CODE},read-only=on"),
        format!("-blockdev driver=file,node-name=fw-vars-file,filename={vars}"),
        "-blockdev driver=qcow2,node-name=fw-vars,file=fw-vars-file".into(),
        format!(
            "-blockdev driver=file,node-name=disk0-file,filename={disk},cache.direct=on,aio=native,discard=unmap"
        ),
        "-blockdev driver=qcow2,node-name=disk0,file=disk0-file,discard=unmap".into(),
        format!("-device {disk_dev},bootindex=1,werror=stop,rerror=stop"),
    ];
    let devices = [
        // No legacy VGA, and a USB controller only for Windows, which has
        // no virtio-input driver: less emulated hardware.
        format!("-device bochs-display,edid=on,xres={w},yres={h}"),
        pointer.into(),
        format!("-chardev socket,id=qmp,path={qmp},server=on,wait=off"),
        "-mon chardev=qmp,mode=control".into(),
        format!("-chardev socket,id=qga0,path={qga},server=on,wait=off"),
        "-device virtio-serial-pci".into(),
        "-device virtserialport,chardev=qga0,name=org.qemu.guest_agent.0".into(),
    ];
    // Values never contain spaces: names and uuids are validated and paths
    // are checked in `opt_path`.
    Ok(args
        .iter()
        .chain(&rtc)
        .chain(&media)
        .chain(&devices)
        .chain(&network)
        .chain(&time_sync)
        .chain(&qga_order)
        .chain(&vnc)
        .flat_map(|a| a.split(' ').map(str::to_owned))
        .collect())
}

/// A path as a QEMU option value: UTF-8, no spaces or control characters,
/// and commas doubled (QEMU's escape for `,` in `key=value,...`).
fn opt_path(path: &Path) -> Result<String> {
    let s = path
        .to_str()
        .with_context(|| format!("path {} is not UTF-8", path.display()))?;
    if s.chars().any(|c| c == ' ' || c.is_control()) {
        bail!("path {s:?} contains spaces or control characters");
    }
    Ok(s.replace(',', ",,"))
}

/// Creates the VM disk as a qcow2 overlay on the cached base image, or
/// blank without one (installer ISOs). The backing format is always given
/// (`-F`), so it is never probed.
pub async fn create_disk(base: Option<&Path>, disk: &Path, size_gib: u64) -> Result<()> {
    // qemu-img would silently overwrite an existing disk.
    ensure!(!disk.exists(), "{} already exists", disk.display());
    let mut cmd = Command::new("qemu-img");
    cmd.args(["create", "-q", "-f", "qcow2"]);
    if let Some(base) = base {
        cmd.args(["-F", "qcow2", "-b"]).arg(base);
    }
    run_tool(
        cmd.arg(disk).arg(format!("{size_gib}G")),
        Duration::from_secs(30),
    )
    .await
    .context("cannot create the VM disk")?;
    Ok(())
}

/// The firmware variable template for `firmware`.
fn vars_template(firmware: Firmware) -> &'static str {
    match firmware {
        Firmware::SecureBoot => OVMF_VARS,
        Firmware::Uefi => OVMF_VARS_NO_KEYS,
    }
}

/// Copies the firmware variable template into a per-VM qcow2, so internal
/// snapshots can include it. Only the daemon reads the template; QEMU gets
/// the copy.
pub async fn create_vars(vars: &Path, firmware: Firmware) -> Result<()> {
    ensure!(!vars.exists(), "{} already exists", vars.display());
    run_tool(
        Command::new("qemu-img")
            .args(["convert", "-q", "-f", "raw", "-O", "qcow2"])
            .arg(vars_template(firmware))
            .arg(vars),
        Duration::from_secs(30),
    )
    .await
    .context("cannot create the firmware variable store")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NetProfile;

    fn vm() -> VmConfig {
        VmConfig {
            name: "dev".into(),
            uuid: "4f1c2b9e-0d3a-4c5e-8f7a-1b2c3d4e5f60".into(),
            image: "ubuntu-26.04".into(),
            vcpus: 2,
            memory_mib: 2048,
            disk_gib: 20,
            net: NetProfile::Offline,
            agent_control: false,
            throwaway_of: None,
            forwards: vec![],
            vnc: false,
            cdrom: None,
            machine: Os::Linux,
        }
    }

    /// S4: the golden command line.
    #[test]
    fn golden_argv() {
        let got = argv(
            &vm(),
            Path::new("/d/vms/dev"),
            Path::new("/r/vms/dev"),
            None,
            None,
            Agent::Deb,
            Media::Seed,
        )
        .unwrap();
        let want = "\
-name guest=dev,debug-threads=on -uuid 4f1c2b9e-0d3a-4c5e-8f7a-1b2c3d4e5f60 \
-nodefaults -no-user-config -display none -msg timestamp=on \
-sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny \
-machine pc-q35-10.2,accel=kvm,smm=on,dump-guest-core=off,mem-merge=off,vmport=off,pflash0=fw-code,pflash1=fw-vars \
-global driver=cfi.pflash01,property=secure,value=on \
-global ICH9-LPC.disable_s3=1 -global ICH9-LPC.disable_s4=1 \
-cpu host,-svm,-vmx -smp 2 -m 2048 \
-blockdev driver=file,node-name=fw-code,filename=/usr/share/OVMF/OVMF_CODE_4M.secboot.fd,read-only=on \
-blockdev driver=file,node-name=fw-vars-file,filename=/d/vms/dev/vars.qcow2 \
-blockdev driver=qcow2,node-name=fw-vars,file=fw-vars-file \
-blockdev driver=file,node-name=disk0-file,filename=/d/vms/dev/disk.qcow2,cache.direct=on,aio=native,discard=unmap \
-blockdev driver=qcow2,node-name=disk0,file=disk0-file,discard=unmap \
-device virtio-blk-pci,drive=disk0,bootindex=1,werror=stop,rerror=stop \
-blockdev driver=file,node-name=seed,filename=/d/vms/dev/seed.iso,read-only=on \
-device virtio-blk-pci,drive=seed \
-device bochs-display,edid=on,xres=1280,yres=800 \
-device virtio-tablet-pci \
-chardev socket,id=qmp,path=/r/vms/dev/qmp.sock,server=on,wait=off \
-mon chardev=qmp,mode=control \
-chardev socket,id=qga0,path=/r/vms/dev/qga.sock,server=on,wait=off \
-device virtio-serial-pci \
-device virtserialport,chardev=qga0,name=org.qemu.guest_agent.0 \
-nic none \
-smbios type=11,value=io.systemd.credential:systemd.extra-unit.systemd-networkd-wait-online.service= \
-smbios type=11,value=io.systemd.credential:systemd.extra-unit.systemd-time-wait-sync.service=";
        assert_eq!(got.join(" "), want);
    }

    /// A VM from an ISO: the seed's two arguments make way for a CD-ROM
    /// drive, with the ISO (raw, read-only) or empty, and the guest gets
    /// none of the systemd credentials for Stallo's cloud guests; nothing
    /// else changes.
    #[test]
    fn golden_cdrom() {
        let (d, r) = (Path::new("/d/vms/dev"), Path::new("/r/vms/dev"));
        let with = |agent, media| argv(&vm(), d, r, None, None, agent, media).map(|a| a.join(" "));
        let credentials = " \
-smbios type=11,value=io.systemd.credential:systemd.extra-unit.systemd-networkd-wait-online.service= \
-smbios type=11,value=io.systemd.credential:systemd.extra-unit.systemd-time-wait-sync.service=";
        let full = with(Agent::Deb, Media::Seed).unwrap();
        assert!(full.ends_with(credentials));
        let seed = full.replace(credentials, "");
        let seed_args = "-blockdev driver=file,node-name=seed,filename=/d/vms/dev/seed.iso,read-only=on \
                         -device virtio-blk-pci,drive=seed";
        assert!(seed.contains(seed_args));
        assert!(seed.ends_with("-nic none"));
        let iso = Path::new("/d/images/fedora-44-workstation.iso");
        assert_eq!(
            with(Agent::Manual, Media::Cdrom(Some(iso))).unwrap(),
            seed.replace(
                seed_args,
                "-blockdev driver=file,node-name=cd0-file,filename=/d/images/fedora-44-workstation.iso,read-only=on \
                 -blockdev driver=raw,node-name=cd0,file=cd0-file,read-only=on \
                 -device ide-cd,id=cd0,drive=cd0,bus=ide.0,bootindex=2"
            )
        );
        assert_eq!(
            with(Agent::Manual, Media::Cdrom(None)).unwrap(),
            seed.replace(seed_args, "-device ide-cd,id=cd0,bus=ide.0,bootindex=2")
        );
        // Nor with the internet profile, or an agent that would be
        // preinstalled.
        let inet = VmConfig {
            net: NetProfile::Internet,
            ..vm()
        };
        let a = argv(
            &inet,
            d,
            r,
            Some(9),
            None,
            Agent::Preinstalled,
            Media::Cdrom(None),
        )
        .unwrap();
        assert!(!a.join(" ").contains("smbios"), "{a:?}");
        // The ISO's path is escaped or refused like the others.
        assert!(with(Agent::Manual, Media::Cdrom(Some(Path::new("/a b.iso")))).is_err());
        let comma = with(Agent::Manual, Media::Cdrom(Some(Path::new("/a,b.iso")))).unwrap();
        assert!(comma.contains("filename=/a,,b.iso,read-only=on"));
    }

    fn windows() -> VmConfig {
        VmConfig {
            machine: Os::Windows,
            memory_mib: 4096,
            disk_gib: 64,
            image: "local-win11".into(),
            cdrom: Some("local-win11".into()),
            vnc: true,
            ..vm()
        }
    }

    /// The Windows profile: Hyper-V enlightenments, no HPET, an RTC in
    /// local time, an AHCI disk, a USB tablet and no systemd credentials.
    #[test]
    fn golden_windows() {
        let got = argv(
            &windows(),
            Path::new("/d/vms/dev"),
            Path::new("/r/vms/dev"),
            None,
            Some(Path::new("/r/vnc/dev/vnc.sock")),
            Agent::Manual,
            Media::Cdrom(Some(Path::new("/d/images/local-win11.iso"))),
        )
        .unwrap();
        let want = "\
-name guest=dev,debug-threads=on -uuid 4f1c2b9e-0d3a-4c5e-8f7a-1b2c3d4e5f60 \
-nodefaults -no-user-config -display none -msg timestamp=on \
-sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny \
-machine pc-q35-10.2,accel=kvm,smm=on,dump-guest-core=off,mem-merge=off,vmport=off,pflash0=fw-code,pflash1=fw-vars,hpet=off \
-global driver=cfi.pflash01,property=secure,value=on \
-global ICH9-LPC.disable_s3=1 -global ICH9-LPC.disable_s4=1 \
-cpu host,-svm,-vmx,hv-relaxed,hv-vapic,hv-spinlocks=0x1fff,hv-vpindex,hv-runtime,hv-synic,hv-stimer,hv-time,hv-frequencies,hv-tlbflush,hv-ipi -smp 2 -m 4096 \
-blockdev driver=file,node-name=fw-code,filename=/usr/share/OVMF/OVMF_CODE_4M.secboot.fd,read-only=on \
-blockdev driver=file,node-name=fw-vars-file,filename=/d/vms/dev/vars.qcow2 \
-blockdev driver=qcow2,node-name=fw-vars,file=fw-vars-file \
-blockdev driver=file,node-name=disk0-file,filename=/d/vms/dev/disk.qcow2,cache.direct=on,aio=native,discard=unmap \
-blockdev driver=qcow2,node-name=disk0,file=disk0-file,discard=unmap \
-device ide-hd,drive=disk0,bus=ide.1,bootindex=1,werror=stop,rerror=stop \
-rtc base=localtime,driftfix=slew \
-blockdev driver=file,node-name=cd0-file,filename=/d/images/local-win11.iso,read-only=on \
-blockdev driver=raw,node-name=cd0,file=cd0-file,read-only=on \
-device ide-cd,id=cd0,drive=cd0,bus=ide.0,bootindex=2 \
-device bochs-display,edid=on,xres=1280,yres=800 \
-device qemu-xhci,id=usb -device usb-tablet,bus=usb.0 \
-chardev socket,id=qmp,path=/r/vms/dev/qmp.sock,server=on,wait=off \
-mon chardev=qmp,mode=control \
-chardev socket,id=qga0,path=/r/vms/dev/qga.sock,server=on,wait=off \
-device virtio-serial-pci \
-device virtserialport,chardev=qga0,name=org.qemu.guest_agent.0 \
-nic none \
-vnc unix:/r/vnc/dev/vnc.sock";
        assert_eq!(got.join(" "), want);
        assert!(!want.contains("smbios") && !want.contains("virtio-tablet"));

        let (d, r) = (Path::new("/d"), Path::new("/r"));
        let vnc = Some(Path::new("/r/vnc.sock"));
        // The internet profile gets an e1000e NIC, still without option ROM.
        let inet = VmConfig {
            net: NetProfile::Internet,
            ..windows()
        };
        let a = argv(&inet, d, r, Some(9), vnc, Agent::Manual, Media::Cdrom(None)).unwrap();
        assert!(a.contains(&"e1000e,netdev=net0,mac=52:54:00:4f:1c:2b,romfile=".to_owned()));
        // passt's end of the socketpair, as for Linux guests.
        assert!(a.contains(&"stream,id=net0,server=off,addr.type=fd,addr.str=9".to_owned()));
        assert!(!a.iter().any(|x| x.contains("virtio-net") || x == "-nic"));
        // A Windows VM always comes from an ISO.
        assert!(argv(&windows(), d, r, None, vnc, Agent::Manual, Media::Seed).is_err());
    }

    /// S4: the security-relevant flags, checked one by one.
    #[test]
    fn security_flags() {
        let a = argv(
            &vm(),
            Path::new("/d"),
            Path::new("/r"),
            None,
            None,
            Agent::Deb,
            Media::Seed,
        )
        .unwrap();
        let after = |flag: &str| {
            a.windows(2)
                .filter(|w| w[0] == flag)
                .map(|w| w[1].clone())
                .collect::<Vec<_>>()
        };
        assert!(a.contains(&"-nodefaults".to_owned()));
        assert!(after("-cpu")[0].contains("-svm,-vmx"));
        let machine = &after("-machine")[0];
        assert!(machine.contains("mem-merge=off") && machine.contains("vmport=off"));
        assert!(after("-sandbox")[0].contains("spawn=deny"));
        assert_eq!(after("-nic"), ["none"]);
        assert!(after("-netdev").is_empty());
        assert!(
            !a.iter()
                .any(|x| x == "-vnc" || x.contains("tcp:") || x.contains("host="))
        );
    }

    #[test]
    fn paths_are_escaped_or_refused() {
        assert_eq!(opt_path(Path::new("/a,b/c")).unwrap(), "/a,,b/c");
        assert!(opt_path(Path::new("/a b")).is_err());
        assert!(opt_path(Path::new("/a\nb")).is_err());
        let a = argv(
            &vm(),
            Path::new("/x,y"),
            Path::new("/r"),
            None,
            None,
            Agent::Deb,
            Media::Seed,
        )
        .unwrap();
        assert!(a.iter().any(|x| x.contains("filename=/x,,y/disk.qcow2,")));
        for name in ["a,b", "a b", "a\nb"] {
            let bad = VmConfig {
                name: name.into(),
                ..vm()
            };
            assert!(
                argv(
                    &bad,
                    Path::new("/d"),
                    Path::new("/r"),
                    None,
                    None,
                    Agent::Deb,
                    Media::Seed
                )
                .is_err()
            );
        }
    }

    /// The internet profile: one virtio NIC on the passt socket, no
    /// `-nic none`, and the boot waits for the network again.
    #[test]
    fn internet_nic() {
        let inet = VmConfig {
            net: NetProfile::Internet,
            ..vm()
        };
        let a = argv(
            &inet,
            Path::new("/d"),
            Path::new("/r"),
            Some(9),
            None,
            Agent::Deb,
            Media::Seed,
        )
        .unwrap();
        let offline = argv(
            &vm(),
            Path::new("/d"),
            Path::new("/r"),
            None,
            None,
            Agent::Deb,
            Media::Seed,
        )
        .unwrap();
        let tail = &a[a.len() - 6..];
        assert_eq!(
            tail.join(" "),
            "-netdev stream,id=net0,server=off,addr.type=fd,addr.str=9 \
             -device virtio-net-pci,netdev=net0,mac=52:54:00:4f:1c:2b,romfile= \
             -smbios type=11,value=io.systemd.credential:systemd.extra-unit.systemd-time-wait-sync.service="
        );
        assert_eq!(a[..a.len() - 6], offline[..offline.len() - 6]);
        assert_eq!(a[a.len() - 2..], offline[offline.len() - 2..]);
        assert!(!a.iter().any(|x| x == "-nic" || x.contains(WAIT_ONLINE)));
        // The profile and the socket go together.
        assert!(
            argv(
                &inet,
                Path::new("/d"),
                Path::new("/r"),
                None,
                None,
                Agent::Deb,
                Media::Seed
            )
            .is_err()
        );
        assert!(
            argv(
                &vm(),
                Path::new("/d"),
                Path::new("/r"),
                Some(9),
                None,
                Agent::Deb,
                Media::Seed
            )
            .is_err()
        );
    }

    /// A preinstalled guest agent waits for cloud-init, on either profile.
    #[test]
    fn preinstalled_agent_waits_for_cloud_init() {
        let (d, r) = (Path::new("/d"), Path::new("/r"));
        let deb = argv(&vm(), d, r, None, None, Agent::Deb, Media::Seed).unwrap();
        let pre = argv(&vm(), d, r, None, None, Agent::Preinstalled, Media::Seed).unwrap();
        assert_eq!(pre[..deb.len()], deb[..]);
        // base64 of "[Unit]\nAfter=cloud-final.service\n".
        assert_eq!(
            pre[deb.len()..],
            [
                "-smbios",
                "type=11,value=io.systemd.credential.binary:systemd.unit-dropin.qemu-guest-agent.service=W1VuaXRdCkFmdGVyPWNsb3VkLWZpbmFsLnNlcnZpY2UK"
            ]
        );
        let inet = VmConfig {
            net: NetProfile::Internet,
            ..vm()
        };
        let a = argv(&inet, d, r, Some(9), None, Agent::Preinstalled, Media::Seed).unwrap();
        assert!(a.contains(&pre[pre.len() - 1]));
    }

    /// S4: VNC only on a Unix socket, only when the VM asks for it.
    #[test]
    fn vnc_on_unix_socket() {
        let on = VmConfig { vnc: true, ..vm() };
        let sock = Path::new("/r/vnc/dev/vnc.sock");
        let a = argv(
            &on,
            Path::new("/d"),
            Path::new("/r"),
            None,
            Some(sock),
            Agent::Deb,
            Media::Seed,
        )
        .unwrap();
        let offline = argv(
            &vm(),
            Path::new("/d"),
            Path::new("/r"),
            None,
            None,
            Agent::Deb,
            Media::Seed,
        )
        .unwrap();
        assert_eq!(a[a.len() - 2..], ["-vnc", "unix:/r/vnc/dev/vnc.sock"]);
        assert_eq!(a[..a.len() - 2], offline[..]);
        assert!(!a.iter().any(|x| x.contains("tcp:") || x.contains("host=")));
        assert!(
            argv(
                &on,
                Path::new("/d"),
                Path::new("/r"),
                None,
                None,
                Agent::Deb,
                Media::Seed
            )
            .is_err()
        );
        assert!(
            argv(
                &vm(),
                Path::new("/d"),
                Path::new("/r"),
                None,
                Some(sock),
                Agent::Deb,
                Media::Seed
            )
            .is_err()
        );
        assert!(
            argv(
                &on,
                Path::new("/d"),
                Path::new("/r"),
                None,
                Some(Path::new("/a b")),
                Agent::Deb,
                Media::Seed
            )
            .is_err()
        );
    }
}
