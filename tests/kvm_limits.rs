//! A real memory limit on a running VM: shrinking `memory.max` below what
//! QEMU uses gets QEMU OOM-killed inside its cgroup, the host stays fine,
//! and the daemon notices and cleans up.

mod common;

use std::fs;

use common::Daemon;

#[test]
#[ignore = "boots a VM; run with STALLO_IT=1"]
fn memory_limit_is_enforced() {
    if !common::enabled() {
        return;
    }
    let d = Daemon::start("limits", "");
    d.ok(&[
        "new", "lim", "--image", &d.image, "--cpus", "1", "--mem", "1G", "--disk", "10G",
    ]);
    d.assert_safe("lim");

    let cg = d.vm_cgroup("lim");
    // memory.events counts the whole subtree (default cgroup2 mount without
    // memory_localevents), so the VM's OOM kill shows up at the unit.
    let oom_kills = || -> u64 {
        fs::read_to_string(d.cgroup.join("memory.events"))
            .unwrap()
            .lines()
            .find_map(|l| l.strip_prefix("oom_kill "))
            .unwrap()
            .parse()
            .unwrap()
    };
    let before = oom_kills();
    // Far below what a booted guest uses; swap is off for the VM.
    fs::write(cg.join("memory.max"), b"64M").unwrap();

    let stopped = common::wait_for(std::time::Duration::from_secs(30), || {
        let out = d.stallo(&["ls"]);
        out.status.success() && String::from_utf8_lossy(&out.stdout).contains("stopped")
    });
    assert!(stopped.is_ok(), "QEMU was not stopped by the memory limit");
    assert!(oom_kills() > before, "no OOM kill recorded");
    assert!(!cg.exists(), "cgroup not cleaned up");
    assert!(!d.vm_runtime("lim").exists());

    // The daemon is fine and the VM can be removed.
    d.ok(&["rm", "lim", "--yes"]);
    assert!(!d.vm_dir("lim").exists());
}

/// `stallo set --cpus/--mem`: refused while the VM runs; after a stop, the
/// VM boots with the new size.
#[test]
#[ignore = "boots a VM; run with STALLO_IT=1"]
fn resized_vm_boots_with_new_size() {
    if !common::enabled() {
        return;
    }
    let d = Daemon::start("resize", "");
    d.ok(&[
        "new", "rsz", "--image", &d.image, "--cpus", "1", "--mem", "1G", "--disk", "10G",
    ]);
    let out = d.stallo(&["set", "rsz", "--mem", "2G"]);
    assert!(!out.status.success(), "resized while running");
    assert!(String::from_utf8_lossy(&out.stderr).contains("stop it first"));
    d.ok(&["stop", "rsz"]);
    d.ok(&["set", "rsz", "--cpus", "2", "--mem", "2G"]);
    d.ok(&["start", "rsz"]);
    d.assert_safe("rsz");
    let cpus = d.ok(&["exec", "rsz", "--", "nproc"]);
    assert_eq!(cpus.trim(), "2");
    let mem = d.ok(&["exec", "rsz", "--", "grep", "MemTotal", "/proc/meminfo"]);
    let kib: u64 = mem.split_whitespace().nth(1).unwrap().parse().unwrap();
    // 2 GiB less what the kernel keeps for itself; well above the old 1 GiB.
    assert!(kib > 1_700_000, "{mem}");
    d.ok(&["stop", "rsz"]);
    d.ok(&["rm", "rsz", "--yes"]);
}
