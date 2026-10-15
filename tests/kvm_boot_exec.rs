//! M0 gate: boot, exec, files, limits, graceful stop, second boot, clean
//! removal, admission.

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::Instant;

use common::Daemon;

#[test]
#[ignore = "boots a VM; run with STALLO_IT=1"]
fn boot_exec_stop_rm() {
    if !common::enabled() {
        return;
    }
    // A small budget so the second VM below is refused: on this 28 GiB host
    // 10% is about 2.8 GiB, room for one 2 GiB VM (2.25 GiB with QEMU
    // overhead). The unit's MemoryMax=3G backs this up.
    let d = Daemon::start("boot", "[host]\nmemory_budget_pct = 10\n");

    // Create, start, wait for the guest agent.
    let started = Instant::now();
    let out = d.ok(&[
        "new", "dev", "--image", &d.image, "--cpus", "2", "--mem", "2G", "--disk", "20G",
    ]);
    let ready = started.elapsed();
    assert!(out.contains("ready in"), "{out}");
    eprintln!(
        "MEASURE create -> guest agent ready: {:.1} s",
        ready.as_secs_f64()
    );
    d.assert_safe("dev");

    // Limits on vm-dev.
    let cg = d.vm_cgroup("dev");
    let read = |f: &str| fs::read_to_string(cg.join(f)).unwrap().trim().to_owned();
    assert_eq!(read("memory.max"), ((2048u64 + 256) << 20).to_string());
    assert_eq!(read("memory.swap.max"), "0");
    assert_eq!(read("cpu.max"), "200000 100000");
    assert_eq!(read("pids.max"), "512");
    let qemu = d.vm_pids("dev")[0];
    let adj = fs::read_to_string(format!("/proc/{qemu}/oom_score_adj")).unwrap();
    assert_eq!(adj.trim(), "500");

    // S3: the runtime dirs are private.
    let mode = fs::metadata(&d.runtime).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o700);
    let mode = fs::metadata(d.vm_runtime("dev"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o700);
    // S2: API socket is 0600.
    let mode = fs::metadata(&d.socket).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    // S1: neither the daemon nor QEMU has an IP socket.
    common::assert_no_ip_sockets(d.daemon_pid());
    common::assert_no_ip_sockets(qemu);

    // Exec: guest kernel, exit code pass-through, guest user vs admin.
    let uname = d.ok(&["exec", "dev", "--", "uname", "-a"]);
    assert!(uname.starts_with("Linux dev "), "{uname}");
    let out = d.stallo(&["exec", "dev", "--", "sh", "-c", "exit 7"]);
    assert_eq!(out.status.code(), Some(7));
    assert_eq!(d.ok(&["exec", "dev", "--", "id", "-un"]).trim(), "agent");
    assert_eq!(
        d.ok(&["exec", "dev", "--admin", "--", "id", "-un"]).trim(),
        "root"
    );
    let t = Instant::now();
    d.ok(&["exec", "dev", "--", "true"]);
    eprintln!("MEASURE exec true: {} ms", t.elapsed().as_millis());
    // Offline: the guest sees no network device besides loopback.
    assert_eq!(
        d.ok(&["exec", "dev", "--", "ls", "/sys/class/net"]).trim(),
        "lo"
    );
    assert_no_wait_online(&d);

    // File round trip through the guest agent.
    let src = d.base.join("blob");
    let back = d.base.join("blob.back");
    let blob: Vec<u8> = (0..300_000u32).map(|i| (i * 7 + i / 251) as u8).collect();
    fs::write(&src, &blob).unwrap();
    d.ok(&["cp", src.to_str().unwrap(), "dev:/home/agent/blob"]);
    d.ok(&["cp", "dev:/home/agent/blob", back.to_str().unwrap()]);
    assert_eq!(fs::read(&back).unwrap(), blob);

    // QEMU overhead: resident memory outside the guest RAM mapping.
    let (total_kib, guest_kib) = rss_split(qemu, 2048 << 10);
    eprintln!(
        "MEASURE QEMU RSS {} MiB (guest RAM {} MiB, QEMU itself {} MiB); cgroup memory.current {} MiB",
        total_kib >> 10,
        guest_kib >> 10,
        (total_kib - guest_kib) >> 10,
        read("memory.current").parse::<u64>().unwrap() >> 20
    );

    // Admission: a second VM does not fit the budget and leaves nothing.
    let out = d.stallo(&[
        "new", "two", "--image", &d.image, "--cpus", "1", "--mem", "1G", "--disk", "10G",
    ]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("budget"));
    assert!(!d.vm_dir("two").exists());
    assert!(!d.vm_cgroup("two").exists());

    // Graceful stop within 60 s.
    let t = Instant::now();
    d.ok(&["stop", "dev"]);
    let stop = t.elapsed();
    eprintln!("MEASURE graceful stop: {:.1} s", stop.as_secs_f64());
    // Well under the 60 s power-off budget, so it was not a forced quit.
    assert!(stop.as_secs() < 55, "stop took {stop:?}");
    assert!(d.ok(&["ls"]).contains("stopped"));
    assert!(!cg.exists());
    assert!(!d.vm_runtime("dev").exists());

    // Second boot: ready again, and the file survived.
    let t = Instant::now();
    // `start` waits for the guest agent.
    assert_eq!(d.ok(&["start", "dev"]).trim(), "dev  started");
    eprintln!(
        "MEASURE start (second boot) -> guest agent ready: {:.1} s",
        t.elapsed().as_secs_f64()
    );
    d.assert_safe("dev");
    assert_no_wait_online(&d);
    fs::remove_file(&back).unwrap();
    d.ok(&["cp", "dev:/home/agent/blob", back.to_str().unwrap()]);
    assert_eq!(fs::read(&back).unwrap(), blob);
    d.ok(&["stop", "dev"]);

    // Remove: no files, cgroups or sockets left.
    d.ok(&["rm", "dev", "--yes"]);
    assert!(!d.vm_dir("dev").exists());
    assert!(fs::read_dir(d.data.join("vms")).unwrap().next().is_none());
    assert!(
        fs::read_dir(d.runtime.join("vms"))
            .unwrap()
            .next()
            .is_none()
    );
    assert!(
        !fs::read_dir(&d.cgroup)
            .unwrap()
            .any(|e| { e.unwrap().file_name().to_string_lossy().starts_with("vm-") })
    );
}

/// systemd-networkd-wait-online never started in the guest: without a
/// NIC it would hold the boot for 2 minutes (see qemu.rs and seed.rs).
fn assert_no_wait_online(d: &Daemon) {
    let started = d.ok(&[
        "exec",
        "dev",
        "--",
        "systemctl",
        "show",
        "-P",
        "ExecMainStartTimestampMonotonic",
        "systemd-networkd-wait-online.service",
    ]);
    assert_eq!(started.trim(), "0", "wait-online ran");
}

/// Resident KiB of `pid`: (total, in mappings of at least `guest_kib`,
/// i.e. guest RAM).
fn rss_split(pid: u32, guest_kib: u64) -> (u64, u64) {
    let smaps = fs::read_to_string(format!("/proc/{pid}/smaps")).unwrap();
    let (mut size, mut total, mut guest) = (0, 0, 0);
    for line in smaps.lines() {
        let mut f = line.split_whitespace();
        match (f.next(), f.next().and_then(|v| v.parse::<u64>().ok())) {
            (Some("Size:"), Some(v)) => size = v,
            (Some("Rss:"), Some(v)) => {
                total += v;
                if size >= guest_kib {
                    guest += v;
                }
            }
            _ => {}
        }
    }
    (total, guest)
}

#[test]
fn harness_rejects_unsafe_argv() {
    let ok = |extra: &[&str]| {
        let mut v: Vec<String> = [
            "/usr/bin/qemu-system-x86_64",
            "-smp",
            "2",
            "-m",
            "2048",
            "-nic",
            "none",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        v.extend(extra.iter().map(|s| s.to_string()));
        std::panic::catch_unwind(|| common::check_argv(&v)).is_ok()
    };
    assert!(ok(&["-cpu", "host,-svm,-vmx"]));
    for bad in [
        &["-netdev", "user,id=n0"][..],
        &["--netdev", "user,id=n0"],
        &["-device", "virtio-net-pci"],
        &["-device", "rtl8139,netdev=n0"],
        &["-nic", "user"],
        &["-vnc", ":0"],
        &["-gdb", "tcp::1234"],
        &["-chardev", "socket,id=c,host=0.0.0.0,port=1"],
        &["-smp", "8"],
        &["-m", "4096"],
    ] {
        assert!(!ok(bad), "{bad:?}");
    }
}

#[test]
fn s1_check_detects_a_tcp_listener() {
    let _listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let caught = std::panic::catch_unwind(|| common::assert_no_ip_sockets(std::process::id()));
    assert!(caught.is_err());
}
