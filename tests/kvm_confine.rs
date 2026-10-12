//! Confinement of a real QEMU: with the daemon's Landlock ruleset and
//! seccomp filter, QEMU can open its own disk but not another VM's disk, a
//! cgroup control file or another VM's QMP socket, even when asked to over
//! QMP (which is what a guest that escaped into QEMU could do).

mod common;

use std::fs;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use serde_json::json;
use stallo::paths::safe_remove;
use stallo::qmp::Qmp;
use stallo::{confine, qemu};

#[test]
#[ignore = "starts a (paused) QEMU with KVM; run with STALLO_IT=1"]
fn confined_qemu_cannot_open_other_vms() {
    if !common::enabled() {
        return;
    }
    let (_lock, cache_root) = common::exclusive();
    let base = cache_root.join("confine");
    let run_root = fs::canonicalize(common::env_path("XDG_RUNTIME_DIR")).unwrap();
    let runtime = run_root.join("stallo-it-confine");
    safe_remove(&cache_root, &base).unwrap();
    safe_remove(&run_root, &runtime).unwrap();
    let result = std::panic::catch_unwind(|| run(&base, &runtime));
    safe_remove(&cache_root, &base).unwrap();
    safe_remove(&run_root, &runtime).unwrap();
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

fn run(base: &Path, runtime: &Path) {
    let own = base.join("vms/dev");
    let other = base.join("vms/other");
    let rt = runtime.join("vms/dev");
    for d in [&own, &other, &rt] {
        fs::create_dir_all(d).unwrap();
    }
    let image = base.join("base.qcow2");
    for disk in [&image, &own.join(qemu::DISK), &other.join(qemu::DISK)] {
        let ok = std::process::Command::new("qemu-img")
            .args(["create", "-q", "-f", "qcow2"])
            .arg(disk)
            .arg("16M")
            .status()
            .unwrap()
            .success();
        assert!(ok);
    }
    for f in [qemu::VARS, qemu::STATE, qemu::SEED] {
        fs::write(own.join(f), b"").unwrap();
    }
    for f in qemu::SCREEN_FILES {
        fs::write(rt.join(f), b"").unwrap();
    }

    let qmp_sock = rt.join(qemu::QMP_SOCK);
    let mut argv: Vec<String> = [
        qemu::QEMU,
        "-nodefaults",
        "-no-user-config",
        "-display",
        "none",
        "-sandbox",
        "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
        "-machine",
        "pc-q35-10.2,accel=kvm",
        "-cpu",
        "host,-svm,-vmx",
        "-smp",
        "1",
        "-m",
        "64",
        "-S",
        "-device",
        "bochs-display",
        "-mon",
        "chardev=qmp,mode=control",
        "-nic",
        "none",
        "-chardev",
    ]
    .map(str::to_owned)
    .into();
    argv.push(format!(
        "socket,id=qmp,path={},server=on,wait=off",
        qmp_sock.display()
    ));
    common::check_argv(&argv);

    let rt_main = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    // Writable without confinement, so the denial below is Landlock's.
    let cgroup = own_cgroup().join("cgroup.procs");
    fs::OpenOptions::new()
        .write(true)
        .open(&cgroup)
        .expect("run this test in a cgroup the user owns (e.g. a user service)");
    rt_main.block_on(async {
        let mut cmd = tokio::process::Command::new(&argv[0]);
        cmd.args(&argv[1..]).stdin(Stdio::null()).kill_on_drop(true);
        let rules = confine::qemu_rules(&own, &rt, &image);
        confine::confine_on_exec(&mut cmd, confine::build(&rules).unwrap());
        let mut child = cmd.spawn().unwrap();

        common::wait_for(Duration::from_secs(10), || qmp_sock.exists()).unwrap();
        let qmp = Qmp::connect(&qmp_sock, Duration::from_secs(5))
            .await
            .unwrap();
        let open = |name: &str, path: &Path, read_only: bool| {
            json!({"driver": "file", "node-name": name,
                   "filename": path.to_str().unwrap(), "read-only": read_only})
        };

        // Its own disk opens read-write.
        qmp.execute(
            "blockdev-add",
            Some(open("own", &own.join(qemu::DISK), false)),
        )
        .await
        .unwrap();

        // Another VM's disk, even read-only, and a cgroup control file are
        // denied by the kernel.
        for (name, path, ro) in [
            ("other", other.join(qemu::DISK), true),
            ("cg", cgroup.clone(), false),
        ] {
            let err = qmp
                .execute("blockdev-add", Some(open(name, &path, ro)))
                .await
                .unwrap_err();
            assert!(
                format!("{err:#}").contains("Permission denied"),
                "{}: {err:#}",
                path.display()
            );
        }

        // QMP can also write files: not into another VM's directory.
        let target = other.join("vm.toml");
        let err = qmp
            .execute(
                "screendump",
                Some(json!({"filename": target.to_str().unwrap()})),
            )
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("Permission denied"), "{err:#}");
        assert!(!target.exists());

        // Nor can it connect to another VM's QMP socket (or the daemon's).
        let other_qmp = other.join(qemu::QMP_SOCK);
        let _listener = std::os::unix::net::UnixListener::bind(&other_qmp).unwrap();
        let err = qmp
            .execute(
                "chardev-add",
                Some(json!({"id": "x", "backend": {"type": "socket", "data": {
                    "server": false,
                    "addr": {"type": "unix", "data": {"path": other_qmp.to_str().unwrap()}}
                }}})),
            )
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("Permission denied"), "{err:#}");

        // No io_uring (its operations would bypass the seccomp filter).
        let pid = child.id().unwrap();
        for fd in fs::read_dir(format!("/proc/{pid}/fd")).unwrap() {
            let target = fs::read_link(fd.unwrap().path()).unwrap_or_default();
            assert!(!target.to_string_lossy().contains("io_uring"));
        }

        let _ = qmp.execute("quit", None).await;
        let _ = tokio::time::timeout(Duration::from_secs(10), child.wait()).await;
    });
}

/// This test process's cgroup directory.
fn own_cgroup() -> std::path::PathBuf {
    let text = fs::read_to_string("/proc/self/cgroup").unwrap();
    let rel = text.lines().find_map(|l| l.strip_prefix("0::")).unwrap();
    Path::new("/sys/fs/cgroup").join(rel.trim_start_matches('/'))
}
