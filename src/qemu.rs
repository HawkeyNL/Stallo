//! The QEMU command line and the per-VM disk files.
//!
//! `argv` is a pure function so the full command line is pinned by a golden
//! test: one machine type, a fixed device set, no defaults, seccomp sandbox,
//! and no network device unless a profile adds one.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use tokio::process::Command;

use crate::config::{NetProfile, VmConfig};
use crate::run_tool;

pub const QEMU: &str = "/usr/bin/qemu-system-x86_64";
/// Secure Boot firmware and the matching variable store with Microsoft keys
/// (Ubuntu's shim is signed by Microsoft).
pub const OVMF_CODE: &str = "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd";
pub const OVMF_VARS: &str = "/usr/share/OVMF/OVMF_VARS_4M.ms.fd";

/// Guest screen size; screenshots and pointer coordinates use it 1:1.
pub const SCREEN: (u32, u32) = (1280, 800);

/// File names inside the VM directory and the VM runtime directory.
pub const DISK: &str = "disk.qcow2";
pub const VARS: &str = "vars.qcow2";
pub const SEED: &str = "seed.iso";
pub const QMP_SOCK: &str = "qmp.sock";
pub const QGA_SOCK: &str = "qga.sock";

const WAIT_ONLINE: &str = "systemd-networkd-wait-online.service";

/// The machine type is pinned rather than the moving `q35` alias, so a QEMU
/// upgrade does not silently change the virtual hardware under saved VM
/// state. Ubuntu 26.04 ships QEMU 10.2.
pub const MACHINE: &str = "pc-q35-10.2";

/// Builds the QEMU argv (without the program) for `vm`.
pub fn argv(vm: &VmConfig, vm_dir: &Path, rt_dir: &Path) -> Result<Vec<String>> {
    // Names and uuids end up inside option strings; never trust the caller.
    vm.validate()?;
    let network = match vm.net {
        // No NIC means no link ever comes online, and Ubuntu's boot then
        // waits 2 minutes for systemd-networkd-wait-online. An empty
        // `systemd.extra-unit.*` credential masks it (systemd >= 256).
        NetProfile::Offline => [
            "-nic none".to_owned(),
            format!(
                "-smbios type=11,value=io.systemd.credential:systemd.extra-unit.{WAIT_ONLINE}="
            ),
        ],
        NetProfile::Internet => bail!("only the offline network profile is available"),
    };
    let file = |dir: &Path, name: &str| opt_path(&dir.join(name));
    let (disk, vars, seed) = (
        file(vm_dir, DISK)?,
        file(vm_dir, VARS)?,
        file(vm_dir, SEED)?,
    );
    let (qmp, qga) = (file(rt_dir, QMP_SOCK)?, file(rt_dir, QGA_SOCK)?);
    let (name, uuid) = (&vm.name, &vm.uuid);
    let (w, h) = SCREEN;

    let args = [
        format!("-name guest={name},debug-threads=on"),
        format!("-uuid {uuid}"),
        "-nodefaults -no-user-config -display none -msg timestamp=on".into(),
        "-sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny".into(),
        // mem-merge=off: no KSM page sharing between guests and the host
        // (side channels). vmport=off: no VMware backdoor port.
        format!(
            "-machine {MACHINE},accel=kvm,smm=on,dump-guest-core=off,mem-merge=off,vmport=off,pflash0=fw-code,pflash1=fw-vars"
        ),
        "-global driver=cfi.pflash01,property=secure,value=on".into(),
        // Guests cannot suspend or hibernate and wedge automation.
        "-global ICH9-LPC.disable_s3=1 -global ICH9-LPC.disable_s4=1".into(),
        // No nested virtualisation: it exposes KVM's nested code to the guest.
        format!("-cpu host,-svm,-vmx -smp {} -m {}", vm.vcpus, vm.memory_mib),
        format!("-blockdev driver=file,node-name=fw-code,filename={OVMF_CODE},read-only=on"),
        format!("-blockdev driver=file,node-name=fw-vars-file,filename={vars}"),
        "-blockdev driver=qcow2,node-name=fw-vars,file=fw-vars-file".into(),
        format!(
            "-blockdev driver=file,node-name=disk0-file,filename={disk},cache.direct=on,aio=native,discard=unmap"
        ),
        "-blockdev driver=qcow2,node-name=disk0,file=disk0-file,discard=unmap".into(),
        "-device virtio-blk-pci,drive=disk0,bootindex=1,werror=stop,rerror=stop".into(),
        format!("-blockdev driver=file,node-name=seed,filename={seed},read-only=on"),
        "-device virtio-blk-pci,drive=seed".into(),
        // No legacy VGA and no USB controller: less emulated hardware.
        format!("-device bochs-display,edid=on,xres={w},yres={h}"),
        "-device virtio-tablet-pci".into(),
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
        .chain(&network)
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

/// Creates the VM disk as a qcow2 overlay on the cached base image. The
/// backing format is always given (`-F`), so it is never probed.
pub async fn create_disk(base: &Path, disk: &Path, size_gib: u64) -> Result<()> {
    // qemu-img would silently overwrite an existing disk.
    ensure!(!disk.exists(), "{} already exists", disk.display());
    run_tool(
        Command::new("qemu-img")
            .args(["create", "-q", "-f", "qcow2", "-F", "qcow2", "-b"])
            .arg(base)
            .arg(disk)
            .arg(format!("{size_gib}G")),
        Duration::from_secs(30),
    )
    .await
    .context("cannot create the VM disk")?;
    Ok(())
}

/// Copies the firmware variable template into a per-VM qcow2, so internal
/// snapshots can include it.
pub async fn create_vars(vars: &Path) -> Result<()> {
    ensure!(!vars.exists(), "{} already exists", vars.display());
    run_tool(
        Command::new("qemu-img")
            .args(["convert", "-q", "-f", "raw", "-O", "qcow2", OVMF_VARS])
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
        }
    }

    /// S4: the golden command line.
    #[test]
    fn golden_argv() {
        let got = argv(&vm(), Path::new("/d/vms/dev"), Path::new("/r/vms/dev")).unwrap();
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
-smbios type=11,value=io.systemd.credential:systemd.extra-unit.systemd-networkd-wait-online.service=";
        assert_eq!(got.join(" "), want);
    }

    /// S4: the security-relevant flags, checked one by one.
    #[test]
    fn security_flags() {
        let a = argv(&vm(), Path::new("/d"), Path::new("/r")).unwrap();
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
        let a = argv(&vm(), Path::new("/x,y"), Path::new("/r")).unwrap();
        assert!(a.iter().any(|x| x.contains("filename=/x,,y/disk.qcow2,")));
        for name in ["a,b", "a b", "a\nb"] {
            let bad = VmConfig {
                name: name.into(),
                ..vm()
            };
            assert!(argv(&bad, Path::new("/d"), Path::new("/r")).is_err());
        }
    }

    #[test]
    fn only_offline() {
        let vm = VmConfig {
            net: NetProfile::Internet,
            ..vm()
        };
        assert!(argv(&vm, Path::new("/d"), Path::new("/r")).is_err());
    }
}
