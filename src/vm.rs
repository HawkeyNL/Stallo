//! VM lifecycle: create, start, wait for the guest agent, exec, stop, remove.
//!
//! `vm.toml` on disk is the source of truth; whether a VM runs is kept in
//! memory only. Lifecycle operations on one VM are serialised by a per-name
//! lock. Callers must not cancel these futures midway (the daemon runs
//! every request in its own task to completion). Each QEMU process is owned
//! by a watcher task that, when QEMU exits
//! for any reason, kills and removes the VM cgroup and runtime directory
//! before the VM counts as stopped.

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;
use tokio::process::Command;
use tokio::sync::watch;

use crate::cgroup::{Cgroups, Limits};
use crate::config::{DaemonConfig, NetProfile, VmConfig, new_uuid, validate_name};
use crate::host::{self, Ask, HostInfo};
use crate::paths::{Paths, ensure_private_dir, safe_remove};
use crate::qga::{ExecOutput, Qga};
use crate::qmp::Qmp;
use crate::{confine, images, qemu, seed};

/// Graceful power-off budget before QEMU is told to quit.
const POWERDOWN_TIMEOUT: Duration = Duration::from_secs(60);
/// How long `wait_ready` waits for the guest agent.
pub const READY_TIMEOUT: Duration = Duration::from_secs(300);
/// Each exec output stream is cut at this size.
pub const EXEC_OUTPUT_CAP: usize = 1 << 20;
pub const EXEC_DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);
pub const EXEC_MAX_TIMEOUT: Duration = Duration::from_secs(3600);
/// How long a guest command waits for the one before it to finish.
const QGA_BUSY_WAIT: Duration = Duration::from_secs(30);

/// What a new VM looks like.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewVm {
    pub name: String,
    pub image: String,
    pub vcpus: u32,
    pub memory_mib: u64,
    pub disk_gib: u64,
    pub net: NetProfile,
}

/// A running QEMU process.
pub struct Running {
    pub config: VmConfig,
    pub pid: u32,
    pub qmp: Qmp,
    qga_sock: PathBuf,
    /// One guest-agent operation at a time.
    qga_lock: tokio::sync::Mutex<()>,
    /// Paused by the disk watchdog.
    disk_full: AtomicBool,
    /// Becomes `true` once QEMU has exited and everything is cleaned up.
    exited: watch::Receiver<bool>,
}

impl Running {
    async fn wait_exited(&self, limit: Duration) -> bool {
        let mut rx = self.exited.clone();
        tokio::time::timeout(limit, rx.wait_for(|e| *e))
            .await
            .is_ok()
    }
}

pub struct Manager {
    pub paths: Paths,
    pub config: DaemonConfig,
    cgroups: Cgroups,
    running: Mutex<HashMap<String, Arc<Running>>>,
    /// Per-name lifecycle locks.
    ops: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// Serialises image downloads.
    pulls: tokio::sync::Mutex<()>,
    /// Serialises admission: checking what fits and starting it is atomic.
    admission: tokio::sync::Mutex<()>,
}

impl Manager {
    pub fn new(paths: Paths, config: DaemonConfig, cgroups: Cgroups) -> Arc<Self> {
        Arc::new(Self {
            paths,
            config,
            cgroups,
            running: Mutex::default(),
            ops: Mutex::default(),
            pulls: tokio::sync::Mutex::default(),
            admission: tokio::sync::Mutex::default(),
        })
    }

    /// Kills leftovers of an earlier daemon: VM cgroups and runtime dirs.
    pub async fn cleanup_leftovers(&self) -> Result<()> {
        self.cgroups.remove_leftovers().await?;
        safe_remove(&self.paths.runtime, &self.paths.vms_runtime_dir())?;
        ensure_private_dir(&self.paths.vms_runtime_dir())?;
        ensure_private_dir(&self.paths.vms_dir())?;
        Ok(())
    }

    // ponytail: entries are never removed (removing one would let two
    // callers hold different locks for one name); the map grows by the
    // number of distinct VM names ever used.
    async fn lock(&self, name: &str) -> tokio::sync::OwnedMutexGuard<()> {
        let lock = self
            .ops
            .lock()
            .unwrap()
            .entry(name.to_owned())
            .or_default()
            .clone();
        lock.lock_owned().await
    }

    pub fn running(&self, name: &str) -> Option<Arc<Running>> {
        self.running.lock().unwrap().get(name).cloned()
    }

    pub fn all_running(&self) -> Vec<Arc<Running>> {
        self.running.lock().unwrap().values().cloned().collect()
    }

    /// All defined VMs, sorted by name.
    pub fn list(&self) -> Result<Vec<VmConfig>> {
        let mut vms = Vec::new();
        for entry in fs::read_dir(self.paths.vms_dir())? {
            let entry = entry?;
            match VmConfig::load(&entry.path()) {
                Ok(cfg) => vms.push(cfg),
                Err(e) => tracing::warn!("skipping {}: {e:#}", entry.path().display()),
            }
        }
        vms.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(vms)
    }

    pub fn load(&self, name: &str) -> Result<VmConfig> {
        self.check_exists(name)?;
        VmConfig::load(&self.paths.vm_dir(name))
    }

    /// Validates `name` and checks that its directory exists, before any
    /// lock is taken for it.
    fn check_exists(&self, name: &str) -> Result<()> {
        validate_name(name)?;
        ensure!(
            self.paths.vm_dir(name).exists(),
            "no VM named {name}; see `stallo ls`"
        );
        Ok(())
    }

    /// Downloads and verifies an image unless it is cached.
    pub async fn pull(&self, id: &str) -> Result<()> {
        let entry = images::find(id)?;
        let _guard = self.pulls.lock().await;
        images::pull(&self.paths, &entry).await
    }

    /// Creates the VM's directory, disk, firmware variables, password and
    /// seed. On failure nothing is left behind.
    pub async fn create(&self, new: &NewVm) -> Result<VmConfig> {
        validate_name(&new.name)?;
        if new.net != NetProfile::Offline {
            bail!("only the offline network profile is available in this version");
        }
        let cfg = VmConfig {
            name: new.name.clone(),
            uuid: new_uuid()?,
            image: new.image.clone(),
            vcpus: new.vcpus,
            memory_mib: new.memory_mib,
            disk_gib: new.disk_gib,
            net: new.net,
            agent_control: false,
        };
        cfg.validate()?;
        // Refuse early, before downloading or writing anything.
        self.admit(&cfg, cfg.disk_gib << 30)?;
        self.pull(&cfg.image).await?;

        let _op = self.lock(&new.name).await;
        let dir = self.paths.vm_dir(&new.name);
        // Claims the name atomically: fails if the directory exists.
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::AlreadyExists => {
                    anyhow::anyhow!("a VM named {} already exists", new.name)
                }
                _ => anyhow::Error::from(e).context(format!("cannot create {}", dir.display())),
            })?;
        let result = self.populate(&cfg).await;
        if result.is_err()
            && let Err(e) = safe_remove(&self.paths.data, &dir)
        {
            tracing::error!("{}: cleanup after failed create: {e:#}", new.name);
        }
        result.map(|()| cfg)
    }

    async fn populate(&self, cfg: &VmConfig) -> Result<()> {
        let dir = self.paths.vm_dir(&cfg.name);
        let entry = images::find(&cfg.image)?;
        let base = images::image_path(&self.paths, &cfg.image);
        let info = images::check_image(&base).await?;
        ensure!(
            cfg.disk_gib << 30 >= info.virtual_size,
            "disk must be at least {} GiB for {}",
            info.virtual_size.div_ceil(1 << 30),
            cfg.image
        );
        qemu::create_disk(&base, &dir.join(qemu::DISK), cfg.disk_gib).await?;
        qemu::create_vars(&dir.join(qemu::VARS)).await?;

        let password = seed::generate_password()?;
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dir.join("secret"))
            .and_then(|mut f| std::io::Write::write_all(&mut f, password.as_bytes()))
            .context("cannot write the VM secret")?;
        let rendered = seed::render(cfg, &seed::hash_password(&password).await?)?;
        seed::build_iso(
            &rendered,
            &images::debs_dir(&self.paths, &entry.release),
            &self.paths.data,
            &dir.join("seed"),
            &dir.join(qemu::SEED),
        )
        .await?;
        // Written last: a directory without vm.toml is never a valid VM.
        cfg.save(&dir)
    }

    /// Starts QEMU in a fresh `vm-<name>` cgroup and connects to QMP.
    pub async fn start(self: &Arc<Self>, name: &str) -> Result<Arc<Running>> {
        self.check_exists(name)?;
        let _op = self.lock(name).await;
        let cfg = self.load(name)?;
        ensure!(self.running(name).is_none(), "{name} is already running");

        let vm_dir = self.paths.vm_dir(name);
        let rt_dir = self.paths.vm_runtime_dir(name);
        safe_remove(&self.paths.runtime, &rt_dir)?;
        ensure_private_dir(&rt_dir)?;
        let argv = qemu::argv(&cfg, &vm_dir, &rt_dir)?;

        // Held until the VM is registered as running, so concurrent starts
        // see each other.
        let _admission = self.admission.lock().await;
        self.admit(&cfg, 0)?;
        match self.spawn(&cfg, &argv).await {
            Ok(running) => Ok(running),
            Err(e) => {
                // Best effort: the error that matters is `e`.
                let _ = self.cgroups.remove_vm(name).await;
                let _ = safe_remove(&self.paths.runtime, &rt_dir);
                Err(e)
            }
        }
    }

    async fn spawn(self: &Arc<Self>, cfg: &VmConfig, argv: &[String]) -> Result<Arc<Running>> {
        let name = &cfg.name;
        let vm_dir = self.paths.vm_dir(name);
        let rt_dir = self.paths.vm_runtime_dir(name);
        let overhead = self.overhead_mib(cfg.memory_mib);
        let limits = Limits {
            memory_max_bytes: (cfg.memory_mib + overhead) << 20,
            vcpus: cfg.vcpus,
        };
        let log_path = vm_dir.join("qemu.log");
        let log = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&log_path)?;
        log.set_permissions(fs::Permissions::from_mode(0o600))?;
        let cg = self.cgroups.create_vm(name, limits).await?;
        let mut cmd = Command::new(qemu::QEMU);
        cmd.args(argv)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log)
            // Own process group: a Ctrl-C meant for a foreground daemon
            // must not reach the guests.
            .process_group(0);
        // Order matters: the cgroup hook opens files the ruleset denies.
        crate::cgroup::move_on_exec(&mut cmd, &cg)?;
        let rules = confine::qemu_rules(
            &vm_dir,
            &rt_dir,
            &images::image_path(&self.paths, &cfg.image),
        );
        confine::confine_on_exec(&mut cmd, confine::build(&rules)?);
        let mut child = cmd.spawn().context("cannot start QEMU")?;
        let pid = child
            .id()
            .expect("a child that was not waited for has a pid");

        let qmp = match self.connect_qmp(&rt_dir, &mut child).await {
            Ok(q) => q,
            Err(e) => {
                let _ = child.start_kill();
                let _ = child.wait().await;
                return Err(e.context(format!("QEMU did not start; see {}", log_path.display())));
            }
        };

        let (tx, rx) = watch::channel(false);
        let running = Arc::new(Running {
            config: cfg.clone(),
            pid,
            qmp,
            qga_sock: rt_dir.join(qemu::QGA_SOCK),
            qga_lock: tokio::sync::Mutex::new(()),
            disk_full: AtomicBool::new(false),
            exited: rx,
        });
        self.running
            .lock()
            .unwrap()
            .insert(name.to_owned(), running.clone());
        tokio::spawn(self.clone().watch(name.clone(), child, tx));
        tracing::info!("{name}: started, pid {pid}");
        Ok(running)
    }

    /// Host resources and what running VMs use.
    pub fn host(&self) -> Result<HostInfo> {
        let running = self.all_running();
        // Each VM counts with its full cgroup limit (guest RAM + overhead).
        let vms: Vec<(u32, u64)> = running
            .iter()
            .map(|r| {
                let m = r.config.memory_mib;
                (r.config.vcpus, m + self.overhead_mib(m))
            })
            .collect();
        // QEMU faults guest RAM in lazily, so MemAvailable does not yet
        // show what running VMs may still take: memory.max - memory.current.
        let unfaulted_mib: u64 = running
            .iter()
            .map(|r| self.cgroups.unused_memory_bytes(&r.config.name) >> 20)
            .sum();
        host::snapshot(&self.paths.data, &self.config.host, &vms, unfaulted_mib)
    }

    /// Whether `cfg` fits next to the running VMs, with `disk_bytes` of new
    /// disk space.
    fn admit(&self, cfg: &VmConfig, disk_bytes: u64) -> Result<()> {
        let ask = Ask {
            vcpus: cfg.vcpus,
            memory_mib: cfg.memory_mib,
            overhead_mib: self.overhead_mib(cfg.memory_mib),
            disk_bytes,
        };
        host::admit(&self.host()?, &ask, &self.config.host)
    }

    /// Continues a paused VM, unless the disk is still below the floor.
    pub async fn resume(&self, name: &str) -> Result<()> {
        self.check_exists(name)?;
        let _op = self.lock(name).await;
        let vm = self
            .running(name)
            .with_context(|| format!("{name} is not running"))?;
        ensure!(vm.status().await? != "running", "{name} is not paused");
        let floor = self.config.host.disk_floor_gib;
        ensure!(
            !host::below_floor(host::disk_free(&self.paths.data)?, floor),
            "the data disk is still below the {floor} GiB floor; free space first"
        );
        // Cleared first, so a watchdog tick after `cont` can pause it again.
        vm.disk_full.store(false, Ordering::Relaxed);
        vm.qmp.execute("cont", None).await?;
        Ok(())
    }

    fn overhead_mib(&self, memory_mib: u64) -> u64 {
        overhead_mib(self.config.host.qemu_overhead_mib, memory_mib)
    }

    /// QEMU creates the QMP socket shortly after start.
    async fn connect_qmp(
        &self,
        rt_dir: &std::path::Path,
        child: &mut tokio::process::Child,
    ) -> Result<Qmp> {
        let sock = rt_dir.join(qemu::QMP_SOCK);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = child.try_wait()? {
                bail!("QEMU exited with {status}");
            }
            if sock.exists() {
                return Qmp::connect(&sock, Duration::from_secs(5)).await;
            }
            ensure!(Instant::now() < deadline, "no QMP socket after 10 s");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Owns the QEMU process until it exits, then cleans up.
    async fn watch(
        self: Arc<Self>,
        name: String,
        mut child: tokio::process::Child,
        tx: watch::Sender<bool>,
    ) {
        let status = child.wait().await;
        tracing::info!("{name}: QEMU exited ({status:?})");
        if let Err(e) = self.cgroups.remove_vm(&name).await {
            tracing::error!("{name}: cgroup cleanup failed: {e:#}");
        }
        if let Err(e) = safe_remove(&self.paths.runtime, &self.paths.vm_runtime_dir(&name)) {
            tracing::error!("{name}: runtime dir cleanup failed: {e:#}");
        }
        self.running.lock().unwrap().remove(&name);
        let _ = tx.send(true);
    }

    /// Waits until the guest agent answers, at most `limit`.
    pub async fn wait_ready(&self, name: &str, limit: Duration) -> Result<Duration> {
        let started = Instant::now();
        let poll = async {
            let mut delay = Duration::from_millis(100);
            loop {
                let vm = self
                    .running(name)
                    .with_context(|| format!("{name} is not running"))?;
                if vm.ping().await.is_ok() {
                    return Ok(started.elapsed());
                }
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(1));
            }
        };
        tokio::time::timeout(limit, poll)
            .await
            .map_err(|_| anyhow::anyhow!("{name}: guest agent not ready after {limit:?}"))?
    }

    /// Powers the VM off: ACPI power button, then `quit` after
    /// [`POWERDOWN_TIMEOUT`], then `cgroup.kill`. With `force`, kills at once.
    pub async fn stop(&self, name: &str, force: bool) -> Result<()> {
        self.check_exists(name)?;
        let _op = self.lock(name).await;
        let vm = self
            .running(name)
            .with_context(|| format!("{name} is not running"))?;
        // A paused guest never sees the power button: go straight to quit.
        let running = vm.status().await.is_ok_and(|s| s == "running");
        if !force && running {
            match vm.qmp.execute("system_powerdown", None).await {
                Ok(_) if vm.wait_exited(POWERDOWN_TIMEOUT).await => return Ok(()),
                Ok(_) => tracing::warn!("{name}: no power-off after {POWERDOWN_TIMEOUT:?}"),
                Err(e) => tracing::warn!("{name}: system_powerdown failed: {e:#}"),
            }
        }
        if !force {
            let _ = vm.qmp.execute("quit", None).await;
            if vm.wait_exited(Duration::from_secs(5)).await {
                return Ok(());
            }
        }
        self.cgroups.kill_vm(name)?;
        ensure!(
            vm.wait_exited(Duration::from_secs(15)).await,
            "{name} did not exit after kill"
        );
        Ok(())
    }

    /// Stops every running VM, gracefully and in parallel.
    pub async fn stop_all(self: &Arc<Self>) {
        let names: Vec<String> = self.running.lock().unwrap().keys().cloned().collect();
        let mut stops = tokio::task::JoinSet::new();
        for name in names {
            let this = self.clone();
            stops.spawn(async move {
                if let Err(e) = this.stop(&name, false).await {
                    tracing::error!("{name}: stop failed: {e:#}");
                }
            });
        }
        stops.join_all().await;
    }

    /// Deletes a stopped VM and all its files. Also works on a directory
    /// that a failed create left without `vm.toml`.
    pub async fn remove(&self, name: &str) -> Result<()> {
        self.check_exists(name)?;
        let _op = self.lock(name).await;
        ensure!(
            self.running(name).is_none(),
            "{name} is running; stop it first: stallo stop {name}"
        );
        safe_remove(&self.paths.data, &self.paths.vm_dir(name))?;
        Ok(())
    }

    /// Runs `argv` in the guest. Without `admin` it runs as the guest user.
    /// Only one guest command runs per VM at a time.
    pub async fn exec(
        &self,
        name: &str,
        argv: &[String],
        admin: bool,
        limit: Duration,
    ) -> Result<ExecOutput> {
        self.check_exists(name)?;
        ensure!(!argv.is_empty(), "nothing to run");
        ensure!(
            limit >= Duration::from_secs(1),
            "timeout must be at least 1 s"
        );
        ensure!(
            limit <= EXEC_MAX_TIMEOUT,
            "timeout is at most {EXEC_MAX_TIMEOUT:?}"
        );
        let vm = self
            .running(name)
            .with_context(|| format!("{name} is not running"))?;
        let (path, args) = guest_command(argv, admin, limit);
        // One guest-agent operation per VM at a time; do not queue forever.
        let _qga = tokio::time::timeout(QGA_BUSY_WAIT, vm.qga_lock.lock())
            .await
            .map_err(|_| anyhow::anyhow!("{name} is busy with another guest command"))?;
        let mut qga = Qga::connect(&vm.qga_sock, Duration::from_secs(5)).await?;
        let started = Instant::now();
        let out = qga.exec(&path, &args, limit, EXEC_OUTPUT_CAP).await?;
        // The scope's SIGKILL shows up as signal 9.
        ensure!(
            !(out.exit_code == 137 && started.elapsed() >= limit),
            "command timed out after {limit:?} and was killed"
        );
        Ok(out)
    }
}

impl Running {
    async fn ping(&self) -> Result<()> {
        let _qga = self.qga_lock.lock().await;
        let mut qga = Qga::connect(&self.qga_sock, Duration::from_secs(2)).await?;
        qga.ping().await
    }

    /// Marks the VM as paused by the disk watchdog and pauses it. Returns
    /// false if it already was.
    pub async fn pause_disk_full(&self) -> Result<bool> {
        if self.disk_full.swap(true, Ordering::Relaxed) {
            return Ok(false);
        }
        if let Err(e) = self.qmp.execute("stop", None).await {
            // Not paused: let the next tick try again.
            self.disk_full.store(false, Ordering::Relaxed);
            return Err(e);
        }
        Ok(true)
    }

    /// What `ls` shows: QEMU's run state, e.g. `running`, `paused` or
    /// `io-error`, or `paused (disk full)` after the watchdog paused it.
    pub async fn state(&self) -> String {
        match self.status().await {
            Ok(s) if s == "paused" && self.disk_full.load(Ordering::Relaxed) => {
                "paused (disk full)".to_owned()
            }
            Ok(s) => s,
            Err(_) => "unknown".to_owned(),
        }
    }

    /// QEMU's run state, e.g. `running`, `paused` or `io-error`.
    pub async fn status(&self) -> Result<String> {
        let v: Value = self.qmp.execute("query-status", None).await?;
        Ok(v["status"].as_str().unwrap_or("unknown").to_owned())
    }
}

/// QEMU's own memory on top of guest RAM: `max(minimum, memory / 16)`.
pub fn overhead_mib(minimum: u64, memory_mib: u64) -> u64 {
    minimum.max(memory_mib / 16)
}

/// The program and arguments QGA runs for `argv`.
///
/// The guest enforces the time limit: `systemd-run --scope` puts the command
/// in a transient cgroup that is killed with SIGKILL after `limit`, children
/// and `setsid` escapes included. (coreutils `timeout` kills only its direct
/// child, and an orphaned grandchild keeps QGA waiting on the output pipe.)
/// Without `admin`, `setpriv` switches to the guest user in place and
/// `--reset-env` sets HOME, USER and PATH for that user. That user may use
/// sudo in the guest, so this is a convenience, not a security boundary.
fn guest_command(argv: &[String], admin: bool, limit: Duration) -> (String, Vec<String>) {
    // No `$VAR` expansion by systemd-run: argv reaches the command as given.
    let mut args: Vec<String> = [
        "--scope",
        "--quiet",
        "--collect",
        "--expand-environment=no",
        "-p",
        "KillSignal=SIGKILL",
        "-p",
    ]
    .map(str::to_owned)
    .into();
    args.push(format!("RuntimeMaxSec={}ms", limit.as_millis()));
    args.push("--".to_owned());
    if !admin {
        let user = seed::GUEST_USER;
        args.extend([
            "setpriv".to_owned(),
            format!("--reuid={user}"),
            format!("--regid={user}"),
            "--init-groups".to_owned(),
            "--reset-env".to_owned(),
            "--".to_owned(),
        ]);
    }
    args.extend_from_slice(argv);
    ("systemd-run".to_owned(), args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overhead() {
        assert_eq!(overhead_mib(256, 2048), 256);
        assert_eq!(overhead_mib(256, 8192), 512);
    }

    #[test]
    fn guest_commands() {
        let argv = vec!["uname".to_owned(), "-a".to_owned()];
        let (path, args) = guest_command(&argv, true, Duration::from_secs(120));
        assert_eq!(path, "systemd-run");
        assert_eq!(
            args.join(" "),
            "--scope --quiet --collect --expand-environment=no -p KillSignal=SIGKILL -p RuntimeMaxSec=120000ms -- uname -a"
        );
        let (_, args) = guest_command(&argv, false, Duration::from_millis(1500));
        assert_eq!(
            args.join(" "),
            "--scope --quiet --collect --expand-environment=no -p KillSignal=SIGKILL -p RuntimeMaxSec=1500ms -- \
             setpriv --reuid=agent --regid=agent --init-groups --reset-env -- uname -a"
        );
    }
}
