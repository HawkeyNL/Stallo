//! W3 gate, part A: a Windows VM starts with its own swtpm, keeps its TPM
//! through RAM and disk-only snapshots, stops when swtpm dies, and leaves
//! nothing behind. No Windows ISO needed: a dummy ISO (not bootable) is
//! imported as a Windows image, and the firmware alone runs.
//!
//! W4 gate, part B, only with `STALLO_WIN_ISO=/path/to/Win11.iso`: the
//! daemon's Enter presses get the real installer past its CD prompt and
//! Windows Setup shows its first screen. No install.
//!
//! The RFB client lives in the GUI crate; it is compiled in here as a
//! module, as in `kvm_screen.rs`.

mod common;

#[allow(dead_code)]
#[path = "../gui/src/rfb.rs"]
mod rfb;

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::time::{Duration, Instant};

use base64::Engine;
use common::Daemon;
use stallo::api::{Request, ScreenResult, Via, VmDetails};
use stallo::config::VmConfig;
use stallo::tpm;

/// The Windows minimums (and defaults).
const MEMORY_MIB: u64 = 4096;

#[test]
#[ignore = "boots a Windows VM (firmware only); run with STALLO_IT=1"]
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
    // 64 KiB with the ISO 9660 magic, the one thing an import checks.
    let iso = d.base.join("dummy.iso");
    let mut bytes = vec![0; 64 << 10];
    bytes[0x8001..0x8006].copy_from_slice(b"CD001");
    fs::write(&iso, bytes).unwrap();
    d.ok(&[
        "images",
        "import",
        iso.to_str().unwrap(),
        "--os",
        "windows",
        "--id",
        "win11",
    ]);
    d.ok(&[
        "new",
        "win",
        "--image",
        "local-win11",
        "--cpus",
        "2",
        "--mem",
        "4G",
        "--disk",
        "64G",
    ]);
    let vm_dir = d.vm_dir("win");
    let tpm_dir = vm_dir.join(tpm::DIR);
    assert!(!VmConfig::load(&vm_dir).unwrap().machine.is_linux());

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
    assert_swtpm_fds(swtpm, &vm_dir);
    let cd = d.data.join("images/local-win11.iso");
    assert_only_own_fds(qemu, &vm_dir, &cd);

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
    let log = || fs::read_to_string(d.base.join("stallod.log")).unwrap();
    assert!(log().contains("win: swtpm exited"), "{}", log());
    assert!(!log().contains("win: swtpm exited:"), "{}", log());
    assert!(!log().contains("stopping win"), "{}", log());

    // A disk-only snapshot keeps a copy of the TPM state and puts it back.
    let permall = || fs::read(tpm_dir.join("tpm2-00.permall")).unwrap();
    let saved = permall();
    let out = d.ok(&["snap", "win", "d1"]);
    assert!(out.contains("disk only"), "{out}");
    fs::write(tpm_dir.join("tpm2-00.volatilestate"), b"later").unwrap();
    d.ok(&["restore", "win", "d1"]);
    assert_eq!(permall(), saved);
    assert!(!tpm_dir.join("tpm2-00.volatilestate").exists());
    d.ok(&["snap", "win", "--delete", "d1", "--yes"]);
    assert!(!vm_dir.join("tpm-snapshots/d1").exists());

    let out = d.ok(&["restore", "win", "s1"]);
    assert!(out.contains("running"), "{out}");
    d.assert_safe("win");
    let (qemu2, swtpm2) = pair(&d);
    assert_ne!((qemu2, swtpm2), (qemu, swtpm));
    // An swtpm that dies takes the VM with it.
    rustix::process::kill_process(
        rustix::process::Pid::from_raw(swtpm2 as i32).unwrap(),
        rustix::process::Signal::KILL,
    )
    .unwrap();
    assert_gone(&d, &[qemu2, swtpm2]);
    assert!(log().contains("swtpm exited"), "{}", log());
    assert!(log().contains("stopping win"), "{}", log());

    d.ok(&["start", "win", "--no-wait"]);
    let (qemu3, swtpm3) = pair(&d);
    d.ok(&["stop", "win", "--force"]);
    assert_gone(&d, &[qemu3, swtpm3]);

    // swtpm logs errors only: none, and QEMU's TPM backend none either.
    let swtpm_log = fs::read_to_string(vm_dir.join(tpm::LOG)).unwrap();
    assert!(swtpm_log.trim().is_empty(), "swtpm.log: {swtpm_log}");
    let qemu_log = fs::read_to_string(vm_dir.join("qemu.log")).unwrap();
    assert!(
        !qemu_log.to_lowercase().contains("tpm"),
        "qemu.log: {qemu_log}"
    );

    // `rm` takes the TPM state and its snapshot copies with the VM.
    d.ok(&["rm", "win", "--yes"]);
    assert!(!tpm_dir.exists() && !vm_dir.exists());
}

#[test]
#[ignore = "boots the Windows installer to its first Setup screen; run with STALLO_IT=1 and STALLO_WIN_ISO"]
fn windows_setup_starts() {
    if !common::enabled() {
        return;
    }
    let Some(iso) = std::env::var_os("STALLO_WIN_ISO") else {
        eprintln!("skipped: set STALLO_WIN_ISO=/path/to/Win11.iso");
        return;
    };
    let iso = iso
        .to_str()
        .expect("STALLO_WIN_ISO is not UTF-8")
        .to_owned();
    if !Path::new(tpm::SWTPM).exists() {
        eprintln!("skipped: {} is missing", tpm::SWTPM);
        return;
    }
    let need = MEMORY_MIB + 512 + tpm::MEMORY_MIB + common::HEADROOM_MIB;
    let available = Daemon::host_available_mib();
    assert!(
        available >= need,
        "{available} MiB available, {need} MiB needed"
    );
    let d = Daemon::start_without_image("windows-setup", "", MEMORY_MIB);
    let copy = d.data.join("images/local-win11.iso");

    let t = Instant::now();
    d.ok(&["images", "import", &iso, "--os", "windows", "--id", "win11"]);
    eprintln!("MEASURE import: {:.1} s", t.elapsed().as_secs_f64());
    assert_eq!(
        fs::metadata(&copy).unwrap().len(),
        fs::metadata(&iso).unwrap().len()
    );

    let started = Instant::now();
    d.ok(&[
        "new",
        "win",
        "--image",
        "local-win11",
        "--cpus",
        "2",
        "--mem",
        "4G",
        "--disk",
        "64G",
        "--net",
        "offline",
    ]);
    d.assert_safe("win");

    // Setup's first screen: most of the screen lit and blue-dominant
    // (unlike the black CD prompt, boot logo and firmware menu), then
    // stable for 5 s.
    // ponytail: colour heuristic; OCR or a UI tree if it ever misfires.
    let info: VmDetails = serde_json::from_value(
        d.api(Via::Cli, Request::Info { name: "win".into() })
            .unwrap(),
    )
    .unwrap();
    let socket = info.vnc_socket.expect("no VNC socket while running");
    let mut seen = Look::default();
    let setup = common::wait_for(Duration::from_secs(240), || {
        seen = look(&socket);
        seen.setup() || {
            std::thread::sleep(Duration::from_secs(2));
            false
        }
    });
    let to_setup = started.elapsed();
    let shot = settled(&d);
    let saved = d.base.parent().unwrap().join("windows-setup.png");
    fs::write(&saved, &shot.0).unwrap();
    eprintln!("MEASURE screen: {seen:?}; saved {}", saved.display());
    setup.expect("Windows Setup did not show in 240 s");
    assert!(shot.1, "the Setup screen did not settle");
    eprintln!(
        "MEASURE start -> Setup: {:.1} s, settled after {:.1} s",
        to_setup.as_secs_f64(),
        started.elapsed().as_secs_f64()
    );
    let seen = look(&socket);
    assert!(seen.setup(), "Setup went away: {seen:?}");
    if std::env::var_os("STALLO_WIN_SETUP_DEEP").is_some_and(|v| v == "1") {
        click_through_setup(&d, &socket);
    }

    // Setup only read the ISO: the sparse disk holds next to nothing.
    let used: u64 = fs::read_dir(d.vm_dir("win"))
        .unwrap()
        .map(|e| e.unwrap().metadata().unwrap().blocks() * 512)
        .sum();
    eprintln!("MEASURE VM directory: {} MiB", used >> 20);
    assert!(used < 1 << 30, "{used} bytes");

    d.assert_safe("win");
    d.ok(&["stop", "win", "--force"]);
    d.ok(&["rm", "win", "--yes"]);
    d.ok(&["images", "rm", "local-win11", "--yes"]);
    assert!(!copy.exists());
}

/// What a frame looks like: its size, the share of lit pixels and the mean
/// of each colour.
#[derive(Debug, Default)]
struct Look {
    size: (u16, u16),
    lit_pct: usize,
    mean_rgb: [u64; 3],
}

impl Look {
    fn setup(&self) -> bool {
        let [r, g, b] = self.mean_rgb;
        self.size.0 >= 1024 && self.lit_pct > 60 && b > r && b >= g
    }
}

/// The current frame over VNC.
fn frame(socket: &Path) -> rfb::Frame {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let (_session, mut frames) = rfb::Session::connect(socket).await.unwrap();
            tokio::time::timeout(Duration::from_secs(10), frames.changed())
                .await
                .expect("no frame in 10 s")
                .expect("the session ended");
            frames.borrow_and_update().clone()
        })
}

fn look(socket: &Path) -> Look {
    let frame = frame(socket);
    // B G R x.
    let px = frame.pixels.chunks_exact(4);
    let n = px.len().max(1);
    let lit = px
        .clone()
        .filter(|p| p[..3].iter().any(|&c| c > 48))
        .count();
    let mut sum = [0u64; 3];
    for p in px {
        for (s, c) in sum.iter_mut().zip([p[2], p[1], p[0]]) {
            *s += u64::from(c);
        }
    }
    Look {
        size: (frame.width, frame.height),
        lit_pct: lit * 100 / n,
        mean_rgb: sum.map(|s| s / n as u64),
    }
}

/// More than 1% of the pixels differ (a new page, not a caret blink).
fn differs(a: &rfb::Frame, b: &rfb::Frame) -> bool {
    let (a, b) = (a.pixels.chunks_exact(4), b.pixels.chunks_exact(4));
    let n = a.len();
    n != b.len() || a.zip(b).filter(|(p, q)| p[..3] != q[..3]).count() * 100 > n
}

/// `STALLO_WIN_SETUP_DEEP=1`: Enter is Next on the language and keyboard
/// screens. Stops at the setup option screen, before anything that asks for
/// a key, a licence or the disk.
fn click_through_setup(d: &Daemon, socket: &Path) {
    let mut last = frame(socket);
    for page in ["keyboard", "option"] {
        d.api(
            Via::Cli,
            Request::Key {
                name: "win".into(),
                keys: "enter".into(),
            },
        )
        .unwrap();
        let mut next = None;
        let turned = common::wait_for(Duration::from_secs(60), || {
            let (png, stable) = settled(d);
            let now = frame(socket);
            let done = stable && differs(&last, &now);
            next = Some((png, now));
            done
        });
        let (png, now) = next.unwrap();
        let saved = d
            .base
            .parent()
            .unwrap()
            .join(format!("windows-setup-{page}.png"));
        fs::write(&saved, &png).unwrap();
        eprintln!("MEASURE {page} screen saved {}", saved.display());
        turned.unwrap_or_else(|_| panic!("Enter did not lead to the {page} screen"));
        last = now;
    }
}

/// `wait_for_screen` for 5 s of stillness: (PNG, whether it settled).
fn settled(d: &Daemon) -> (Vec<u8>, bool) {
    let shot: ScreenResult = serde_json::from_value(
        d.api(
            Via::Cli,
            Request::WaitForScreen {
                name: "win".into(),
                stable_ms: Some(5000),
                timeout_ms: Some(60_000),
            },
        )
        .unwrap(),
    )
    .unwrap();
    let png = base64::engine::general_purpose::STANDARD
        .decode(shot.png_base64)
        .unwrap();
    (png, shot.stable == Some(true))
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

fn open_fds(pid: u32) -> Vec<(u32, String)> {
    fs::read_dir(format!("/proc/{pid}/fd"))
        .unwrap()
        .map(|fd| {
            let fd = fd.unwrap();
            let n = fd.file_name().to_str().unwrap().parse().unwrap();
            (
                n,
                fs::read_link(fd.path()).unwrap().to_string_lossy().into(),
            )
        })
        .collect()
}

/// swtpm holds stdin/stdout on /dev/null, stderr on its log, its lock
/// file, both ends of its own self-pipe, and exactly two sockets: the
/// control channel from the daemon and the data channel QEMU sent on it.
/// Nothing else leaked in.
fn assert_swtpm_fds(pid: u32, vm_dir: &Path) {
    let fds = open_fds(pid);
    let log = vm_dir.join(tpm::LOG).display().to_string();
    let lock = vm_dir.join(tpm::DIR).join(".lock").display().to_string();
    let (mut sockets, mut pipes) = (0, Vec::new());
    for (n, target) in &fds {
        match n {
            0 | 1 => assert_eq!(target, "/dev/null"),
            2 => assert_eq!(*target, log),
            _ if target.starts_with("socket:") => sockets += 1,
            _ if target.starts_with("pipe:") => pipes.push(target),
            _ => assert_eq!(*target, lock, "swtpm holds fd {n}: {fds:?}"),
        }
    }
    assert_eq!(sockets, 2, "{fds:?}");
    assert!(
        pipes.is_empty() || pipes.len() == 2 && pipes[0] == pipes[1],
        "{fds:?}"
    );
}

/// Every open file of `pid` is a socket, pipe, anonymous inode, `/dev`
/// node, the firmware or the ISO `cd`, or lies in `vm_dir`: nothing of the
/// daemon or of other VMs leaked in.
fn assert_only_own_fds(pid: u32, vm_dir: &Path, cd: &Path) {
    for (_, t) in open_fds(pid) {
        assert!(
            t.starts_with("socket:")
                || t.starts_with("pipe:")
                || t.starts_with("anon_inode:")
                || t.starts_with("/dev/")
                || t.starts_with("/memfd:")
                || t.starts_with("/usr/share/OVMF/")
                || Path::new(&t).starts_with(vm_dir)
                || Path::new(&t) == cd,
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
    common::wait_for(Duration::from_secs(5), || {
        !d.vm_cgroup("win").exists() && !d.vm_runtime("win").exists()
    })
    .expect("the VM's cgroup or runtime directory is left");
    for entry in fs::read_dir(&d.cgroup).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if entry.file_type().unwrap().is_dir() && name != "daemon" && name != "tools" {
            let left = fs::read_to_string(entry.path().join("cgroup.procs")).unwrap();
            assert!(left.trim().is_empty(), "{name} still holds {left}");
        }
    }
    let procs = fs::read_to_string(d.cgroup.join("daemon/cgroup.procs")).unwrap_or_default();
    assert!(!procs.trim().is_empty(), "the daemon is gone");
}
