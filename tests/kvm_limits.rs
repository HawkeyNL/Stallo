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
    d.ok(&["new", "lim", "--cpus", "1", "--mem", "1G", "--disk", "10G"]);
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
