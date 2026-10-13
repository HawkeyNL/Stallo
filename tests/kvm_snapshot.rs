//! M2 snapshots on a real VM: a running guest's process and RAM come back
//! with its snapshot, and the guest agent answers again.

mod common;

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
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

#[test]
#[ignore = "boots a VM; run with STALLO_IT=1"]
fn stopped_snapshots() {
    if !common::enabled() {
        return;
    }
    let d = Daemon::start("snapshot-stopped", "");
    d.ok(&["new", "dev", "--cpus", "2", "--mem", "2G", "--disk", "20G"]);
    let call = |r: Request| d.api(Via::Cli, r);
    let snap = |tag: &str| {
        call(Request::Snapshot {
            name: "dev".into(),
            tag: Some(tag.into()),
        })
        .unwrap()
    };
    let restore = |tag: &str| {
        call(Request::Restore {
            name: "dev".into(),
            tag: Some(tag.into()),
        })
    };

    // A RAM snapshot with state only in RAM, and a file on disk.
    sh(
        &d,
        "echo live > /dev/shm/marker && echo one > /var/tmp/marker && sync",
    );
    let live = snap("live");
    assert_eq!(live["ram"], true);
    d.ok(&["stop", "dev"]);

    // Stopped: a disk-only snapshot.
    let disk = snap("disk");
    eprintln!("MEASURE snapshot of a stopped VM: {disk}");
    assert_eq!(disk["ram"], false);
    let list = call(Request::Snapshots { name: "dev".into() }).unwrap();
    let got: Vec<(String, bool)> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|s| (s["name"].as_str().unwrap().to_owned(), s["ram_bytes"] != 0))
        .collect();
    assert_eq!(got, [("live".into(), true), ("disk".into(), false)]);

    // Change the disk, then go back to the disk-only snapshot.
    d.ok(&["start", "dev"]);
    sh(&d, "echo two > /var/tmp/marker && sync");
    let err = restore("disk").unwrap_err();
    assert!(err.to_string().contains("no RAM state"), "{err}");
    d.ok(&["stop", "dev"]);
    let restored = restore("disk").unwrap();
    assert_eq!(restored["state"], "stopped");
    d.ok(&["start", "dev"]);
    assert_eq!(sh(&d, "cat /var/tmp/marker"), "one");
    assert!(
        exec(&d, "cat /dev/shm/marker")["exit_code"] != 0,
        "booted fresh"
    );
    d.ok(&["stop", "dev"]);

    // A RAM snapshot of a stopped VM starts it from that moment.
    let t = Instant::now();
    let restored = restore("live").unwrap();
    let marker = sh(&d, "cat /dev/shm/marker");
    eprintln!("MEASURE restore RAM snapshot of a stopped VM: {restored}");
    eprintln!("MEASURE stopped restore -> exec ok: {:?}", t.elapsed());
    assert_eq!(restored["state"], "running");
    assert_eq!(marker, "live");
    assert!(t.elapsed() < Duration::from_secs(20));
    d.assert_safe("dev");

    // Clean up: one snapshot while running, one while stopped.
    call(Request::SnapshotDelete {
        name: "dev".into(),
        tag: "live".into(),
    })
    .unwrap();
    d.ok(&["stop", "dev"]);
    call(Request::SnapshotDelete {
        name: "dev".into(),
        tag: "disk".into(),
    })
    .unwrap();
    let list = call(Request::Snapshots { name: "dev".into() }).unwrap();
    assert!(list.as_array().unwrap().is_empty());
}

/// Plan M2-5 / D8: guest pause of a RAM snapshot for 2 GiB and 4 GiB
/// guests, idle and with half the RAM in use, and the restore. 4 GiB only
/// if the host keeps [`common::HEADROOM_MIB`] available besides it.
#[test]
#[ignore = "boots VMs; run with STALLO_IT=1"]
fn pause_times() {
    if !common::enabled() {
        return;
    }
    measure(2048);
    // Guest RAM, QEMU's overhead (its cgroup allows 256 MiB) and slack.
    const OVERHEAD_MIB: u64 = 512;
    let need = 4096 + OVERHEAD_MIB + common::HEADROOM_MIB;
    let available = Daemon::host_available_mib();
    if available < need {
        eprintln!("MEASURE 4 GiB skipped: {available} MiB available, {need} MiB needed");
        return;
    }
    measure(4096);
}

fn measure(mib: u64) {
    let d = Daemon::start_sized(&format!("pause-{mib}"), "", mib);
    let mem = format!("{mib}M");
    d.ok(&["new", "dev", "--cpus", "2", "--mem", &mem, "--disk", "20G"]);
    d.assert_safe("dev");
    let cg = d.vm_cgroup("dev");
    // Every job with the page cache it used: see `sampled`.
    let call = |r: Request| {
        let (v, io) = sampled(&cg, || d.api(Via::Cli, r).unwrap());
        eprintln!("MEASURE io {io}");
        // The RAM image's page cache is dropped after every job
        // (docs/ram-snapshot-io.md).
        let file = |i: usize| io["file"][i].as_u64().unwrap();
        assert!(file(2) <= file(0) + 32, "page cache left behind: {io}");
        v
    };
    let snap = |tag: &str| {
        call(Request::Snapshot {
            name: "dev".into(),
            tag: Some(tag.into()),
        })
    };
    let gib = mib / 1024;
    let idle = snap("idle");
    eprintln!("MEASURE {gib} GiB idle snapshot: {idle}");
    // Half the RAM in use, with data that does not compress or dedupe.
    let fill = mib / 2 - 128;
    sh(
        &d,
        &format!(
            "mount -o remount,size=90% /dev/shm && head -c {fill}M /dev/urandom > /dev/shm/fill"
        ),
    );
    let busy = snap("busy");
    eprintln!("MEASURE {gib} GiB snapshot, {fill} MiB of RAM filled: {busy}");
    let t = Instant::now();
    let restored = call(Request::Restore {
        name: "dev".into(),
        tag: Some("busy".into()),
    });
    sh(&d, "true");
    eprintln!(
        "MEASURE {gib} GiB restore: {restored}; restore -> exec ok {:?}",
        t.elapsed()
    );
    let again = snap("again");
    eprintln!("MEASURE {gib} GiB snapshot after that restore: {again}");
    // Nearly all RAM faulted in (a long-running guest): the RAM image's
    // page cache then has only QEMU's overhead to live in.
    let more = mib * 3 / 4 - fill;
    sh(&d, &format!("head -c {more}M /dev/urandom > /dev/shm/more"));
    let full = snap("full");
    eprintln!(
        "MEASURE {gib} GiB snapshot, {} MiB of RAM filled: {full}",
        fill + more
    );
    let list = call(Request::Snapshots { name: "dev".into() });
    eprintln!("MEASURE {gib} GiB snapshots: {list}");
    let ram_files: u64 = list
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["ram_bytes"].as_u64().unwrap())
        .sum();
    eprintln!(
        "MEASURE {gib} GiB RAM images on disk: {} MiB",
        ram_files >> 20
    );
    // Page cache for the RAM images counts against the VM's cgroup: it
    // must never get QEMU killed.
    let events = std::fs::read_to_string(cg.join("memory.events")).unwrap();
    assert!(events.contains("oom_kill 0"), "{events}");
    let peak = std::fs::read_to_string(cg.join("memory.peak")).unwrap();
    let max = std::fs::read_to_string(cg.join("memory.max")).unwrap();
    eprintln!(
        "MEASURE {gib} GiB cgroup memory.peak {} MiB of memory.max {} MiB",
        peak.trim().parse::<u64>().unwrap() >> 20,
        max.trim().parse::<u64>().unwrap() >> 20
    );
    for tag in ["idle", "busy", "again", "full"] {
        call(Request::SnapshotDelete {
            name: "dev".into(),
            tag: tag.into(),
        });
    }
    assert!(busy["pause_ms"].as_u64().unwrap() < 60_000);
}

/// MiB of `key` in a `memory.stat` (bytes) or `/proc/meminfo` (kB) text.
fn field_mib(text: &str, key: &str) -> u64 {
    let v: u64 = text
        .lines()
        .find_map(|l| l.strip_prefix(key)?.split_whitespace().next()?.parse().ok())
        .unwrap_or(0);
    if key.ends_with(':') { v >> 10 } else { v >> 20 }
}

/// The VM cgroup's `file` and `anon` and the host's `Cached`, in MiB.
fn usage(cg: &Path) -> [u64; 3] {
    let stat = std::fs::read_to_string(cg.join("memory.stat")).unwrap_or_default();
    let info = std::fs::read_to_string("/proc/meminfo").unwrap();
    [
        field_mib(&stat, "file "),
        field_mib(&stat, "anon "),
        field_mib(&info, "Cached:"),
    ]
}

/// Runs `f` and samples [`usage`] every 50 ms meanwhile: returns its result
/// and `[before, peak, after]` per value (host `Cached` also counts other
/// services, so it is noisy).
fn sampled<T>(cg: &Path, f: impl FnOnce() -> T) -> (T, Value) {
    let before = usage(cg);
    let done = AtomicBool::new(false);
    let (out, peak) = std::thread::scope(|s| {
        let sampler = s.spawn(|| {
            let mut peak = before;
            while !done.load(Ordering::Relaxed) {
                for (p, v) in peak.iter_mut().zip(usage(cg)) {
                    *p = (*p).max(v);
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            peak
        });
        let out = f();
        done.store(true, Ordering::Relaxed);
        (out, sampler.join().unwrap())
    });
    let after = usage(cg);
    let at = |i: usize| [before[i], peak[i], after[i]];
    (out, json!({"file": at(0), "anon": at(1), "cached": at(2)}))
}
