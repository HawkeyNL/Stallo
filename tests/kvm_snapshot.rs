//! M2 snapshots on a real VM: a running guest's process and RAM come back
//! with its snapshot, and the guest agent answers again.

mod common;

use std::time::{Duration, Instant};

use serde_json::Value;
use stallo::api::{Request, Via};

use common::Daemon;

fn exec(d: &Daemon, cmd: &str) -> Value {
    d.api(
        Via::Cli,
        Request::Exec {
            name: "dev".into(),
            argv: vec!["sh".into(), "-c".into(), cmd.into()],
            admin: true,
            timeout_s: Some(30),
            stdin: None,
        },
    )
    .unwrap()
}

/// Stdout of `cmd` as root in the guest; the command must succeed.
fn sh(d: &Daemon, cmd: &str) -> String {
    let v = exec(d, cmd);
    assert_eq!(v["exit_code"], 0, "{cmd}: {v}");
    v["stdout"].as_str().unwrap().trim().to_owned()
}

/// The guest's counter: a service that counts every 100 ms in RAM.
fn counter(d: &Daemon) -> u64 {
    sh(d, "cat /dev/shm/counter").parse().unwrap()
}

#[test]
#[ignore = "boots a VM; run with STALLO_IT=1"]
fn running_snapshot_round_trip() {
    if !common::enabled() {
        return;
    }
    let d = Daemon::start("snapshot", "");
    d.ok(&["new", "dev", "--cpus", "2", "--mem", "2G", "--disk", "20G"]);
    d.assert_safe("dev");
    let call = |r: Request| d.api(Via::Cli, r);

    // A process with state only in RAM: a counter service and a tmpfs file.
    sh(
        &d,
        "systemd-run --unit=counter sh -c 'i=0; while :; do i=$((i+1)); echo $i > /dev/shm/counter; sleep 0.1; done' \
         && echo before > /dev/shm/marker && sleep 0.5",
    );
    let pid = sh(&d, "systemctl show -P MainPID counter");

    let taken = call(Request::Snapshot {
        name: "dev".into(),
        tag: Some("s1".into()),
    })
    .unwrap();
    let at_snapshot = counter(&d);
    eprintln!("MEASURE snapshot 2 GiB running: {taken}");
    assert_eq!(taken["name"], "s1");
    assert_eq!(taken["ram"], true);
    assert!(
        taken["pause_ms"].as_u64().is_some(),
        "QEMU paused the guest"
    );

    // Change the RAM state: stop the process, rewrite the marker.
    sh(&d, "systemctl stop counter && echo after > /dev/shm/marker");
    assert_eq!(sh(&d, "systemctl is-active counter || true"), "inactive");

    let t = Instant::now();
    let restored = call(Request::Restore {
        name: "dev".into(),
        tag: None,
    })
    .unwrap();
    // The first exec after the restore reconnects to the guest agent.
    let marker = sh(&d, "cat /dev/shm/marker");
    let restore_to_exec = t.elapsed();
    eprintln!("MEASURE restore 2 GiB running: {restored}");
    eprintln!("MEASURE restore -> exec ok: {restore_to_exec:?}");
    assert_eq!(restored["name"], "s1", "the newest snapshot");
    assert_eq!(restored["state"], "running");
    // Plan item "VM run state after snapshot-load": QEMU pauses the
    // running guest for the load and resumes it itself.
    assert!(
        restored["pause_ms"].as_u64().is_some(),
        "QEMU did not pause and resume the guest: {restored}"
    );
    assert!(restore_to_exec < Duration::from_secs(10));

    assert_eq!(marker, "before", "tmpfs content is back");
    assert_eq!(sh(&d, "systemctl show -P MainPID counter"), pid);
    let after = counter(&d);
    assert!(
        after >= at_snapshot && after < at_snapshot + 100,
        "the counter goes on from the snapshot: {at_snapshot} -> {after}"
    );
    std::thread::sleep(Duration::from_millis(500));
    assert!(counter(&d) > after, "the restored process runs");

    let list = call(Request::Snapshots { name: "dev".into() }).unwrap();
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert!(list[0]["ram_bytes"].as_u64().unwrap() > 0);

    // Refusals: a taken name, an unknown snapshot, and deletion by agents.
    let err = call(Request::Snapshot {
        name: "dev".into(),
        tag: Some("s1".into()),
    })
    .unwrap_err();
    assert!(err.to_string().contains("already exists"), "{err}");
    let err = call(Request::Restore {
        name: "dev".into(),
        tag: Some("nope".into()),
    })
    .unwrap_err();
    assert!(err.to_string().contains("no snapshot named nope"), "{err}");
    d.ok(&["agent", "dev", "on"]);
    let err = d
        .api(
            Via::Mcp,
            Request::SnapshotDelete {
                name: "dev".into(),
                tag: "s1".into(),
            },
        )
        .unwrap_err();
    assert!(
        err.to_string().contains("only available to humans"),
        "{err}"
    );

    // A default name, then deletion (test snapshots hold RAM: clean up).
    let second = call(Request::Snapshot {
        name: "dev".into(),
        tag: None,
    })
    .unwrap();
    eprintln!("MEASURE snapshot 2 GiB running, after a restore: {second}");
    assert_eq!(second["name"], "snap1");
    for tag in ["s1", "snap1"] {
        call(Request::SnapshotDelete {
            name: "dev".into(),
            tag: tag.into(),
        })
        .unwrap();
    }
    let list = call(Request::Snapshots { name: "dev".into() }).unwrap();
    assert!(list.as_array().unwrap().is_empty());
    d.assert_safe("dev");
    assert_eq!(sh(&d, "echo ok"), "ok");
}
