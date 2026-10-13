//! `stallo run`: a command in a throwaway clone of a stopped VM leaves no
//! clone behind, never changes the source, and is cleaned up on Ctrl-C.

mod common;

use std::process::Command;
use std::time::{Duration, Instant};

use common::{Daemon, wait_for};

/// Names of the VM directories in the daemon's data dir.
fn vm_dirs(d: &Daemon) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(d.data.join("vms"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// Whether anything of a clone is left: its directory, runtime dir or
/// cgroup.
fn clone_left(d: &Daemon) -> bool {
    let any_run = |dir: std::path::PathBuf, prefix: &str| {
        std::fs::read_dir(dir).is_ok_and(|entries| {
            entries
                .flatten()
                .any(|e| e.file_name().to_string_lossy().starts_with(prefix))
        })
    };
    any_run(d.data.join("vms"), "run-")
        || any_run(d.runtime.join("vms"), "run-")
        || any_run(d.cgroup.clone(), "vm-run-")
}

#[test]
#[ignore = "boots a VM; run with STALLO_IT=1"]
fn throwaway_runs() {
    if !common::enabled() {
        return;
    }
    let d = Daemon::start("run", "");
    d.ok(&["new", "dev", "--cpus", "2", "--mem", "2G", "--disk", "20G"]);
    d.ok(&[
        "exec",
        "dev",
        "--",
        "sh",
        "-c",
        "echo orig > /home/agent/m && sync",
    ]);
    let err = d.stallo(&["run", "dev", "--", "true"]);
    assert!(
        String::from_utf8_lossy(&err.stderr).contains("needs a stopped VM"),
        "a running source is refused"
    );
    d.ok(&["stop", "dev"]);

    // A run sees the source's disk, its writes go away, its exit code
    // comes back.
    let t = Instant::now();
    let out = d.stallo(&[
        "run",
        "dev",
        "--",
        "sh",
        "-c",
        "cat /home/agent/m; echo changed > /home/agent/m; sync; exit 7",
    ]);
    eprintln!(
        "MEASURE stallo run (boot + command + cleanup): {:?}",
        t.elapsed()
    );
    assert_eq!(out.status.code(), Some(7));
    assert_eq!(String::from_utf8_lossy(&out.stdout), "orig\n");
    assert!(!clone_left(&d), "the clone is gone");
    assert_eq!(vm_dirs(&d), ["dev"]);
    d.ok(&["start", "dev"]);
    let m = d.ok(&["exec", "dev", "--", "cat", "/home/agent/m"]);
    assert_eq!(m, "orig\n", "the source did not change");
    d.ok(&["stop", "dev"]);

    // Ctrl-C while the command runs: the clone is killed and removed.
    let mut child = Command::new(env!("CARGO_BIN_EXE_stallo"))
        .args(["run", "dev", "--", "sleep", "300"])
        .env("STALLO_SOCKET", &d.socket)
        .spawn()
        .unwrap();
    wait_for(Duration::from_secs(120), || {
        d.ok(&["ls"])
            .lines()
            .any(|l| l.starts_with("run-") && l.contains("running"))
    })
    .expect("the clone did not start");
    // The source is locked for the run's whole length: refused at once.
    let t = Instant::now();
    let busy = d.stallo(&["start", "dev"]);
    assert!(!busy.status.success());
    assert!(String::from_utf8_lossy(&busy.stderr).contains("in use by `stallo run`"));
    assert!(t.elapsed() < Duration::from_secs(5));
    std::thread::sleep(Duration::from_secs(3)); // into the command
    let t = Instant::now();
    let pid = child.id().to_string();
    assert!(
        Command::new("kill")
            .args(["-INT", &pid])
            .status()
            .unwrap()
            .success()
    );
    child.wait().unwrap();
    let gone = wait_for(Duration::from_secs(60), || !clone_left(&d));
    eprintln!("MEASURE Ctrl-C -> clone removed: {:?}", t.elapsed());
    assert!(gone.is_ok(), "the clone was not removed after Ctrl-C");
    assert_eq!(vm_dirs(&d), ["dev"]);
    // And the source is free again.
    d.ok(&["start", "dev"]);
    d.assert_safe("dev");
}
