//! W3 gate, part A: a Windows-profile VM starts with its own swtpm, keeps
//! its TPM through a RAM snapshot, and leaves nothing behind. No ISO or
//! guest needed: the firmware alone runs on an empty disk.
//!
//! No catalog image makes a Windows VM yet (local ISO imports come with
//! W1), so the test plants the VM's files itself, as `create` would make
//! them: a blank 64 GiB disk, Secure Boot variables and a `vm.toml` with
//! `machine = "windows"` and an empty CD-ROM drive.

mod common;

use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::Path;
use std::time::Duration;

use common::Daemon;
use stallo::config::{NetProfile, VmConfig, new_uuid};
use stallo::images::{Firmware, Os};
use stallo::{qemu, tpm};

/// The Windows minimums (and defaults).
const MEMORY_MIB: u64 = 4096;

#[test]
#[ignore = "boots a Windows-profile VM (firmware only); run with STALLO_IT=1"]
fn windows_vm_runs_with_swtpm() {
    if !common::enabled() {
        return;
    }
    if !Path::new(tpm::SWTPM).exists() {
        eprintln!("skipped: {} is missing", tpm::SWTPM);
        return;
    }
    // Guest RAM, QEMU's and swtpm's overhead, and slack, as in kvm_iso.rs.
    let need = MEMORY_MIB + 512 + tpm::MEMORY_MIB + common::HEADROOM_MIB;
    let available = Daemon::host_available_mib();
    assert!(
        available >= need,
        "{available} MiB available, {need} MiB needed"
    );
    let d = Daemon::start_without_image("windows", "", MEMORY_MIB);
    plant(&d.vm_dir("win"));
    let vm_dir = d.vm_dir("win");
    let tpm_dir = vm_dir.join(tpm::DIR);

    d.ok(&["start", "win", "--no-wait"]);
    d.assert_safe("win");
    let (qemu, swtpm) = pair(&d);
    let argv = cmdline(qemu).join(" ");
    for want in [
        "-device tpm-crb,tpmdev=tpm0",
        "-tpmdev emulator,id=tpm0,chardev=tpm0-ctrl",
        "usb-tablet",
        "ide-hd,drive=disk0",
    ] {
        assert!(argv.contains(want), "{want}: {argv}");
    }
    // The daemon checked `query-tpm` before it reported the start; the
    // TPM state exists once the firmware initialised the TPM.
    assert_eq!(
        fs::metadata(&tpm_dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
    common::wait_for(Duration::from_secs(30), || {
        tpm_dir.join("tpm2-00.permall").exists()
    })
    .expect("no TPM state after 30 s");
    assert_only_own_fds(swtpm, &vm_dir);
    assert_only_own_fds(qemu, &vm_dir);

    // A RAM snapshot carries the TPM state (QEMU's tpm-emulator fetches it
    // from swtpm), and loads back into the same and into a new swtpm.
    let out = d.ok(&["snap", "win", "s1"]);
    assert!(out.contains("RAM"), "{out}");
    let out = d.ok(&["restore", "win", "s1"]);
    assert!(out.contains("running"), "{out}");
    assert_eq!(pair(&d), (qemu, swtpm), "the restore must keep the VM");

    // A clean stop: QEMU quits (the firmware ignores the power button), and
    // swtpm exits by itself (`,terminate`) instead of being killed.
    d.ok(&["stop", "win"]);
    assert_gone(&d, &[qemu, swtpm]);
    let log = fs::read_to_string(d.base.join("stallod.log")).unwrap();
    assert!(log.contains("win: swtpm exited"), "{log}");
    assert!(!log.contains("win: swtpm exited:"), "{log}");

    let out = d.ok(&["restore", "win", "s1"]);
    assert!(out.contains("running"), "{out}");
    d.assert_safe("win");
    let (qemu2, swtpm2) = pair(&d);
    assert_ne!((qemu2, swtpm2), (qemu, swtpm));
    d.ok(&["stop", "win", "--force"]);
    assert_gone(&d, &[qemu2, swtpm2]);

    // swtpm logs errors only; QEMU's TPM backend none either.
    let swtpm_log = fs::read_to_string(vm_dir.join(tpm::LOG)).unwrap();
    assert!(swtpm_log.trim().is_empty(), "swtpm.log: {swtpm_log}");
    let qemu_log = fs::read_to_string(vm_dir.join("qemu.log")).unwrap();
    assert!(
        !qemu_log.to_lowercase().contains("tpm"),
        "qemu.log: {qemu_log}"
    );

    // `rm` takes the TPM state with the VM.
    d.ok(&["rm", "win", "--yes"]);
    assert!(!tpm_dir.exists() && !vm_dir.exists());
}

/// Writes a stopped Windows VM's files into `dir`.
fn plant(dir: &Path) {
    fs::DirBuilder::new().mode(0o700).create(dir).unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            qemu::create_disk(None, &dir.join(qemu::DISK), 64)
                .await
                .unwrap();
            qemu::create_vars(&dir.join(qemu::VARS), Firmware::SecureBoot)
                .await
                .unwrap();
        });
    fs::DirBuilder::new()
        .mode(0o700)
        .create(dir.join(qemu::STATES))
        .unwrap();
    VmConfig {
        name: "win".into(),
        uuid: new_uuid().unwrap(),
        image: "local-win11".into(),
        vcpus: 2,
        memory_mib: MEMORY_MIB,
        disk_gib: 64,
        net: NetProfile::Offline,
        agent_control: false,
        throwaway_of: None,
        forwards: vec![],
        vnc: true,
        cdrom: None,
        machine: Os::Windows,
    }
    .save(dir)
    .unwrap();
}

fn cmdline(pid: u32) -> Vec<String> {
    fs::read(format!("/proc/{pid}/cmdline"))
        .unwrap()
        .split(|&b| b == 0)
        .filter(|a| !a.is_empty())
        .map(|a| String::from_utf8_lossy(a).into_owned())
        .collect()
}

/// (QEMU, swtpm): the only two processes in the VM's cgroup.
fn pair(d: &Daemon) -> (u32, u32) {
    let pids = d.vm_pids("win");
    assert_eq!(pids.len(), 2, "{pids:?}");
    let is_swtpm = |pid: u32| cmdline(pid)[0] == tpm::SWTPM;
    match (is_swtpm(pids[0]), is_swtpm(pids[1])) {
        (false, true) => (pids[0], pids[1]),
        (true, false) => (pids[1], pids[0]),
        _ => panic!("not one QEMU and one swtpm: {pids:?}"),
    }
}

/// Every open file of `pid` is a socket, pipe, anonymous inode or
/// `/dev` node, or lies in `vm_dir`: nothing of the daemon or of other VMs
/// leaked in.
fn assert_only_own_fds(pid: u32, vm_dir: &Path) {
    for fd in fs::read_dir(format!("/proc/{pid}/fd")).unwrap() {
        let target = fs::read_link(fd.unwrap().path()).unwrap();
        let t = target.to_string_lossy();
        assert!(
            t.starts_with("socket:")
                || t.starts_with("pipe:")
                || t.starts_with("anon_inode:")
                || t.starts_with("/dev/")
                || t.starts_with("/memfd:")
                || t.starts_with("/usr/share/OVMF/")
                || target.starts_with(vm_dir),
            "process {pid} holds {t}"
        );
    }
}

/// The VM's processes, cgroup and runtime directory are gone, and nothing
/// but the daemon is left in the unit.
fn assert_gone(d: &Daemon, pids: &[u32]) {
    common::wait_for(Duration::from_secs(15), || {
        pids.iter()
            .all(|p| !Path::new(&format!("/proc/{p}")).exists())
    })
    .unwrap_or_else(|_| panic!("{pids:?} still exist"));
    assert!(!d.vm_cgroup("win").exists());
    assert!(!d.vm_runtime("win").exists());
    let procs = fs::read_to_string(d.cgroup.join("daemon/cgroup.procs")).unwrap_or_default();
    for entry in fs::read_dir(&d.cgroup).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if entry.file_type().unwrap().is_dir() && name != "daemon" && name != "tools" {
            let left = fs::read_to_string(entry.path().join("cgroup.procs")).unwrap();
            assert!(left.trim().is_empty(), "{name} still holds {left}");
        }
    }
    assert!(!procs.trim().is_empty(), "the daemon is gone");
}
