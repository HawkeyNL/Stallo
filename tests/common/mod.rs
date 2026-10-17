//! Shared harness for the KVM integration tests (`tests/kvm_*.rs`).
//!
//! These tests boot real VMs, so they run only when asked for:
//!
//! ```sh
//! STALLO_IT=1 cargo test -- --ignored --test-threads=1
//! ```
//!
//! The host may run other services, so the rules are enforced, not hoped
//! for:
//! - one VM at a time: tests take a file lock, and refuse to start while any
//!   other QEMU of this user runs;
//! - the daemon runs as a transient systemd user unit (`Delegate=yes`, as in
//!   dev mode) that the kernel confines: `MemoryMax=3G` (guest RAM cap +
//!   1 GiB), `CPUQuota=400%`
//!   (admission then sees 4 cores, so 2 vCPUs fit), only
//!   `AF_UNIX`/`AF_NETLINK` sockets (no IP at all), and
//!   `RuntimeMaxSec=900` as a dead-man switch if the test process dies;
//! - every QEMU in the unit must be offline (`-nic none`, no network
//!   device, and no host listener but a plain VNC Unix socket), with at
//!   most 2 vCPUs and 2 GiB (one measurement may ask for 4 GiB with
//!   [`Daemon::start_sized`], and only while the host keeps 6 GiB
//!   available besides);
//! - data lives in `$HOME/.cache/stallo-it/<test>/`, runtime files in
//!   `$XDG_RUNTIME_DIR/stallo-it-<test>/`;
//! - a guard kills the unit's whole cgroup and removes both directories
//!   through `safe_remove`; it keeps them if anything is still alive.
//!
//! Images are hard-linked from the dev-mode cache, so pull the image once
//! with dev mode first. Tests use `ubuntu-26.04` unless `STALLO_IT_IMAGE_ID`
//! names another catalog image (installer ISOs are named by their test).

#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

use stallo::paths::safe_remove;

pub const MAX_VCPUS: u32 = 2;
pub const MAX_MEMORY_MIB: u64 = 2048;
/// The most any test may ask for, see [`Daemon::start_sized`].
pub const MAX_SIZED_MIB: u64 = 4096;
/// MemAvailable that must remain besides a sized test's VM.
pub const HEADROOM_MIB: u64 = 6144;

pub struct Daemon {
    pub name: String,
    /// The image every test VM is created from, see [`image_id`].
    pub image: String,
    unit: String,
    cache_root: PathBuf,
    pub base: PathBuf,
    pub data: PathBuf,
    run_root: PathBuf,
    pub runtime: PathBuf,
    pub socket: PathBuf,
    pub cgroup: PathBuf,
    /// Largest guest RAM allowed in this daemon's VMs, in MiB.
    max_memory_mib: u64,
    log: PathBuf,
    _lock: fs::File,
}

/// Whether integration tests were asked for. Tests return early otherwise.
pub fn enabled() -> bool {
    let on = std::env::var_os("STALLO_IT").is_some_and(|v| v == "1");
    if !on {
        eprintln!("skipped: set STALLO_IT=1 to run KVM integration tests");
    }
    on
}

/// `STALLO_IT_IMAGE_ID`, or `ubuntu-26.04`.
pub fn image_id() -> String {
    let id = std::env::var("STALLO_IT_IMAGE_ID").unwrap_or_else(|_| "ubuntu-26.04".into());
    stallo::config::validate_image_id(&id).unwrap();
    id
}

pub fn env_path(var: &str) -> PathBuf {
    PathBuf::from(std::env::var_os(var).unwrap_or_else(|| panic!("{var} is not set")))
}

/// The user manager's `app.slice`, where transient units live.
fn app_slice() -> PathBuf {
    let uid = rustix::process::getuid().as_raw();
    PathBuf::from(format!(
        "/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service/app.slice"
    ))
}

/// Kills leftover `stallo-it-*` units of a test process that died without
/// unwinding (Ctrl-C, SIGKILL). Writes `cgroup.kill`; no systemctl needed.
fn kill_stale_units() {
    let Ok(entries) = fs::read_dir(app_slice()) else {
        return;
    };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.starts_with("stallo-it-") && name.ends_with(".service") {
            eprintln!("killing stale unit {name}");
            let _ = fs::write(e.path().join("cgroup.kill"), b"1");
            let _ = wait_for(Duration::from_secs(30), || !e.path().exists());
        }
    }
}

/// Panics if any QEMU of this user is running (for example a dev-mode VM):
/// the test would be a second VM on the host. A QEMU killed by the previous
/// test can leave its cgroup before it is reaped, so give it 10 s to go.
fn assert_no_other_qemu() {
    let uid = rustix::process::getuid().as_raw().to_string();
    let pgrep = || {
        Command::new("pgrep")
            .args(["-u", &uid, "qemu-system"])
            .output()
            .unwrap()
    };
    let _ = wait_for(Duration::from_secs(10), || pgrep().stdout.is_empty());
    let out = pgrep();
    assert!(
        out.stdout.is_empty(),
        "another QEMU of this user is running (pids {}); stop it first",
        String::from_utf8_lossy(&out.stdout).trim()
    );
}

/// Takes the one-VM-at-a-time lock, kills leftovers of killed test runs
/// and checks that no other QEMU runs. Returns the lock (hold it while the
/// VM runs) and the canonical `$HOME/.cache/stallo-it`.
pub fn exclusive() -> (fs::File, PathBuf) {
    let cache_root = env_path("HOME").join(".cache/stallo-it");
    fs::create_dir_all(&cache_root).unwrap();
    let cache_root = fs::canonicalize(cache_root).unwrap();
    let lock = fs::File::create(cache_root.join(".lock")).unwrap();
    lock.lock().unwrap();
    kill_stale_units();
    assert_no_other_qemu();
    (lock, cache_root)
}

impl Daemon {
    /// Starts stallod for test `name` with `config` as its stallod.toml.
    pub fn start(name: &str, config: &str) -> Self {
        Self::start_sized(name, config, MAX_MEMORY_MIB)
    }

    /// MemAvailable of the host, in MiB.
    pub fn host_available_mib() -> u64 {
        let meminfo = fs::read_to_string("/proc/meminfo").unwrap();
        let line = meminfo
            .lines()
            .find(|l| l.starts_with("MemAvailable:"))
            .unwrap();
        line.split_whitespace()
            .nth(1)
            .unwrap()
            .parse::<u64>()
            .unwrap()
            / 1024
    }

    /// [`Daemon::start`] for guests of up to `max_memory_mib` (at most
    /// [`MAX_SIZED_MIB`]). The unit's `MemoryMax` is that plus 1 GiB.
    pub fn start_sized(name: &str, config: &str, max_memory_mib: u64) -> Self {
        Self::start_with(name, config, max_memory_mib, &image_id())
    }

    /// [`Daemon::start_sized`] with catalog image `id` (a cloud image or
    /// an installer ISO) instead of [`image_id`].
    pub fn start_with(name: &str, config: &str, max_memory_mib: u64, id: &str) -> Self {
        Self::launch(name, config, max_memory_mib, Some(id))
    }

    /// [`Daemon::start_sized`] without any image, for a test that imports
    /// its own (`stallo images import`).
    pub fn start_without_image(name: &str, config: &str, max_memory_mib: u64) -> Self {
        Self::launch(name, config, max_memory_mib, None)
    }

    fn launch(name: &str, config: &str, max_memory_mib: u64, id: Option<&str>) -> Self {
        assert!(max_memory_mib <= MAX_SIZED_MIB);
        let home = env_path("HOME");
        let (lock, cache_root) = exclusive();

        let run_root = fs::canonicalize(env_path("XDG_RUNTIME_DIR")).unwrap();
        let base = cache_root.join(name);
        let runtime = run_root.join(format!("stallo-it-{name}"));
        safe_remove(&cache_root, &base).unwrap();
        safe_remove(&run_root, &runtime).unwrap();
        let data = base.join("data");
        let images = data.join("images");
        fs::create_dir_all(&images).unwrap();
        fs::write(data.join("stallod.toml"), config).unwrap();

        // Hard-link the cached image (free) and copy the debs (small), if
        // the image needs any.
        if let Some(id) = id {
            let file = match stallo::images::find(id).map(|e| e.kind) {
                Ok(stallo::images::Kind::Iso) => format!("{id}.iso"),
                _ => format!("{id}.qcow2"),
            };
            let source = home.join(".local/share/stallo-dev/images");
            let image = source.join(&file);
            assert!(
                image.exists(),
                "{} missing; run `stallo images pull {id}` in dev mode first",
                image.display()
            );
            fs::hard_link(&image, images.join(&file)).unwrap();
            let debs = images.join(format!("{id}.debs"));
            if let Ok(cached) = fs::read_dir(source.join(format!("{id}.debs"))) {
                fs::create_dir(&debs).unwrap();
                for e in cached {
                    let e = e.unwrap();
                    fs::copy(e.path(), debs.join(e.file_name())).unwrap();
                }
            }
        }

        let unit = format!("stallo-it-{name}");
        let log = base.join("stallod.log");
        let status = Command::new("systemd-run")
            .args(["--user", "--quiet", "--collect"])
            .arg(format!("--unit={unit}"))
            .args(["-p", "Delegate=yes", "-p", "CPUWeight=50"])
            .args([
                "-p",
                &format!("MemoryMax={}M", max_memory_mib + 1024),
                "-p",
                "MemorySwapMax=0",
                "-p",
                "CPUQuota=400%",
            ])
            .args(["-p", "RestrictAddressFamilies=AF_UNIX AF_NETLINK"])
            .args(["-p", "RuntimeMaxSec=900"])
            .arg(format!("--property=StandardError=file:{}", log.display()))
            .args(["-E", "STALLO_LOG=debug"])
            .arg(env!("CARGO_BIN_EXE_stallod"))
            .arg("--dev")
            .arg("--data-dir")
            .arg(&data)
            .arg("--runtime-dir")
            .arg(&runtime)
            .status()
            .unwrap();
        assert!(status.success(), "systemd-run failed");

        let cgroup_rel = command_stdout(Command::new("systemctl").args([
            "--user",
            "show",
            "-P",
            "ControlGroup",
            &unit,
        ]));
        let cgroup_rel = cgroup_rel.trim();
        assert!(
            cgroup_rel.ends_with(&format!("/{unit}.service")),
            "stallod did not start; see {}",
            log.display()
        );
        let cgroup = Path::new("/sys/fs/cgroup").join(cgroup_rel.trim_start_matches('/'));
        let socket = runtime.join("api.sock");
        let d = Self {
            name: name.to_owned(),
            image: id.unwrap_or_default().to_owned(),
            unit,
            cache_root,
            base,
            data,
            run_root,
            runtime,
            socket,
            cgroup,
            max_memory_mib,
            log,
            _lock: lock,
        };
        wait_for(Duration::from_secs(15), || d.socket.exists())
            .unwrap_or_else(|_| panic!("stallod did not start; see the log above"));
        d
    }

    /// Runs the `stallo` CLI against this daemon.
    pub fn stallo(&self, args: &[&str]) -> Output {
        let out = Command::new(env!("CARGO_BIN_EXE_stallo"))
            .args(args)
            .env("STALLO_SOCKET", &self.socket)
            .output()
            .unwrap();
        eprintln!(
            "$ stallo {}\n{}{}",
            args.join(" "),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        out
    }

    /// Like `stallo`, but the command must succeed; returns stdout.
    pub fn ok(&self, args: &[&str]) -> String {
        let out = self.stallo(args);
        assert!(out.status.success(), "stallo {} failed", args.join(" "));
        String::from_utf8(out.stdout).unwrap()
    }

    /// Sends one API request (as `via`) and returns its data.
    pub fn api(
        &self,
        via: stallo::api::Via,
        request: stallo::api::Request,
    ) -> anyhow::Result<serde_json::Value> {
        let envelope = stallo::api::Envelope { via, request };
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(stallo::api::call(&self.socket, &envelope))
    }

    pub fn vm_cgroup(&self, vm: &str) -> PathBuf {
        self.cgroup.join(format!("vm-{vm}"))
    }

    pub fn daemon_pid(&self) -> u32 {
        command_stdout(
            Command::new("systemctl").args(["--user", "show", "-P", "MainPID", &self.unit]),
        )
        .trim()
        .parse()
        .unwrap()
    }

    /// PIDs in the VM cgroup.
    pub fn vm_pids(&self, vm: &str) -> Vec<u32> {
        pids_in(&self.vm_cgroup(vm))
    }

    /// Panics unless every process in the unit outside the daemon and tools
    /// leaves is an offline, small QEMU or a swtpm on an inherited socket,
    /// and `vm` has one.
    pub fn assert_safe(&self, vm: &str) {
        assert!(!self.vm_pids(vm).is_empty(), "no processes in vm-{vm}");
        for entry in fs::read_dir(&self.cgroup).unwrap().flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !entry.file_type().unwrap().is_dir() || name == "daemon" || name == "tools" {
                continue;
            }
            for pid in pids_in(&entry.path()) {
                let raw = fs::read(format!("/proc/{pid}/cmdline")).unwrap();
                let argv: Vec<String> = raw
                    .split(|&b| b == 0)
                    .filter(|a| !a.is_empty())
                    .map(|a| String::from_utf8_lossy(a).into_owned())
                    .collect();
                if argv[0] == stallo::tpm::SWTPM {
                    // Only a Windows VM has an swtpm, on its own state.
                    let vm = name.strip_prefix("vm-").expect("a VM cgroup");
                    let cfg = stallo::config::VmConfig::load(&self.vm_dir(vm)).unwrap();
                    assert!(!cfg.machine.is_linux(), "swtpm in Linux VM {vm}");
                    check_swtpm_argv(&argv, &self.vm_dir(vm).join(stallo::tpm::DIR));
                } else {
                    check_argv_max(&argv, self.max_memory_mib);
                }
            }
        }
    }

    pub fn vm_dir(&self, vm: &str) -> PathBuf {
        self.data.join("vms").join(vm)
    }

    pub fn vm_runtime(&self, vm: &str) -> PathBuf {
        self.runtime.join("vms").join(vm)
    }
}

fn pids_in(cgroup: &Path) -> Vec<u32> {
    fs::read_to_string(cgroup.join("cgroup.procs"))
        .unwrap_or_default()
        .lines()
        .map(|l| l.parse().unwrap())
        .collect()
}

/// The harness rules for a QEMU command line.
pub fn check_argv(argv: &[String]) {
    check_argv_max(argv, MAX_MEMORY_MIB);
}

fn check_argv_max(argv: &[String], max_memory_mib: u64) {
    // `--nic` and `-nic` are the same option to QEMU.
    let flag = |a: &str| format!("-{}", a.trim_start_matches('-'));
    let after = |name: &str| -> Vec<&str> {
        argv.windows(2)
            .filter(|w| flag(&w[0]) == name)
            .map(|w| w[1].as_str())
            .collect()
    };
    assert!(
        argv[0].ends_with("qemu-system-x86_64"),
        "unexpected process {argv:?}"
    );
    assert_eq!(after("-nic"), ["none"], "VM must be offline: {argv:?}");
    for name in ["-netdev", "-net", "-gdb", "-spice"] {
        assert!(after(name).is_empty(), "VM must have no {name}: {argv:?}");
    }
    // A Unix socket path and nothing else: no options after it (a comma
    // that is not doubled), no websocket, no VNC display.
    for vnc in after("-vnc") {
        assert!(
            vnc.starts_with("unix:")
                && !vnc.replace(",,", "").contains(',')
                && !vnc.contains("websocket"),
            "VNC only on a plain Unix socket: {argv:?}"
        );
    }
    for display in after("-display") {
        assert!(
            !display.contains("vnc"),
            "VM must have no VNC display: {argv:?}"
        );
    }
    for bad in [
        "netdev=",
        "tcp:",
        "host=",
        "virtio-net",
        "e1000",
        "rtl8139",
        "vmxnet",
        "igb",
    ] {
        assert!(
            !argv.iter().any(|a| a.contains(bad)),
            "VM must have no network or host listener ({bad}): {argv:?}"
        );
    }
    // QEMU takes the last occurrence; check every one.
    for smp in after("-smp") {
        let smp: u32 = smp.parse().unwrap();
        assert!(smp <= MAX_VCPUS, "too many vCPUs for this host: {smp}");
    }
    for mem in after("-m") {
        let mem: u64 = mem.parse().unwrap();
        assert!(
            mem <= max_memory_mib,
            "too much memory for this host: {mem}"
        );
    }
}

/// The harness rules for a swtpm command line: the VM's own state in
/// `tpm_dir`, a control channel on an inherited socket, no data socket, no
/// TCP, no socket or log file.
pub fn check_swtpm_argv(argv: &[String], tpm_dir: &Path) {
    assert_eq!(argv[1], "socket", "{argv:?}");
    let state: Vec<&String> = argv
        .windows(2)
        .filter(|w| w[0] == "--tpmstate")
        .map(|w| &w[1])
        .collect();
    assert_eq!(
        state,
        [&format!("dir={}", tpm_dir.display())],
        "swtpm must keep its VM's own state: {argv:?}"
    );
    let ctrl: Vec<&String> = argv
        .windows(2)
        .filter(|w| w[0] == "--ctrl")
        .map(|w| &w[1])
        .collect();
    assert!(
        ctrl.len() == 1
            && ctrl[0].starts_with("type=unixio,clientfd=")
            && ctrl[0].ends_with(",terminate"),
        "swtpm must use an inherited control socket: {argv:?}"
    );
    for bad in ["--server", "--port", "-p", "--daemon", "-d"] {
        assert!(
            !argv.iter().any(|a| a == bad),
            "swtpm must have no {bad}: {argv:?}"
        );
    }
    for bad in ["tcp", "path=", "bindaddr", "file="] {
        assert!(
            !argv.iter().any(|a| a.contains(bad)),
            "swtpm must have no listener ({bad}): {argv:?}"
        );
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if std::thread::panicking()
            && let Ok(log) = fs::read_to_string(&self.log)
        {
            let tail: Vec<&str> = log.lines().rev().take(40).collect();
            eprintln!("--- stallod.log (last 40 lines) ---");
            for line in tail.iter().rev() {
                eprintln!("{line}");
            }
        }
        // Kill the daemon and every VM at once, then wait for the cgroup.
        let _ = fs::write(self.cgroup.join("cgroup.kill"), b"1");
        let gone = wait_for(Duration::from_secs(30), || {
            fs::read_to_string(self.cgroup.join("cgroup.events"))
                .map(|e| e.contains("populated 0"))
                .unwrap_or(true)
        });
        if gone.is_err() {
            // Fail closed: never delete files that live processes use.
            eprintln!(
                "WARNING: unit {} still has processes; kept {} and {}",
                self.unit,
                self.base.display(),
                self.runtime.display()
            );
            return;
        }
        if std::env::var_os("STALLO_IT_KEEP").is_some() {
            eprintln!("kept {}", self.base.display());
            return;
        }
        if let Err(e) = safe_remove(&self.cache_root, &self.base) {
            eprintln!("warning: cannot remove {}: {e}", self.base.display());
        }
        if let Err(e) = safe_remove(&self.run_root, &self.runtime) {
            eprintln!("warning: cannot remove {}: {e}", self.runtime.display());
        }
    }
}

pub fn wait_for(limit: Duration, mut done: impl FnMut() -> bool) -> Result<Duration, ()> {
    let start = Instant::now();
    while start.elapsed() < limit {
        if done() {
            return Ok(start.elapsed());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(())
}

fn command_stdout(cmd: &mut Command) -> String {
    let out = cmd.output().unwrap();
    assert!(out.status.success(), "{cmd:?} failed");
    String::from_utf8(out.stdout).unwrap()
}

/// S1: panics if `pid` holds any TCP or UDP socket.
pub fn assert_no_ip_sockets(pid: u32) {
    let mut inodes = Vec::new();
    for fd in fs::read_dir(format!("/proc/{pid}/fd")).unwrap() {
        let target = fs::read_link(fd.unwrap().path()).unwrap_or_default();
        if let Some(inode) = target
            .to_str()
            .and_then(|t| t.strip_prefix("socket:["))
            .and_then(|t| t.strip_suffix(']'))
        {
            inodes.push(inode.to_owned());
        }
    }
    for table in ["tcp", "tcp6", "udp", "udp6"] {
        let text = fs::read_to_string(format!("/proc/{pid}/net/{table}")).unwrap();
        for line in text.lines().skip(1) {
            let inode = line.split_whitespace().nth(9).unwrap();
            assert!(
                !inodes.iter().any(|i| i == inode),
                "process {pid} owns a {table} socket"
            );
        }
    }
}
