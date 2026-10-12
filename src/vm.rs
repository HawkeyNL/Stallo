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
use std::path::{Path, PathBuf};
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
use crate::{confine, images, input, qemu, seed};

/// Graceful power-off budget before QEMU is told to quit.
const POWERDOWN_TIMEOUT: Duration = Duration::from_secs(60);
/// How long `wait_ready` waits for the guest agent.
pub const READY_TIMEOUT: Duration = Duration::from_secs(300);
/// Each exec output stream is cut at this size.
pub const EXEC_OUTPUT_CAP: usize = 1 << 20;
pub const EXEC_DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);
pub const EXEC_MAX_TIMEOUT: Duration = Duration::from_secs(3600);
/// Largest file chunk read or written in one call. QGA captures at most
/// 16 MiB of output, and a read asks for one byte more to see whether the
/// file goes on.
pub const FILE_MAX: usize = (16 << 20) - 1;
const FILE_TIMEOUT: Duration = Duration::from_secs(120);
/// How long a guest command waits for the one before it to finish.
const QGA_BUSY_WAIT: Duration = Duration::from_secs(30);
/// Largest screendump read back from QEMU. The guest picks the resolution,
/// but bochs-display has 16 MiB of video memory: at most 4 Mi pixels at
/// 32 bpp, a 12 MiB PPM. (A 16 bpp mode with more pixels exceeds this and
/// only fails that VM's own screen tools.)
const MAX_SCREEN_BYTES: u64 = 16 << 20;
/// Screendumps read at once across all VMs, to bound daemon memory.
static SCREENS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);
/// `wait_for_screen` compares frames this often.
const SCREEN_POLL: Duration = Duration::from_millis(250);
pub const SCREEN_DEFAULT_STABLE: Duration = Duration::from_millis(1000);
pub const SCREEN_DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const SCREEN_MAX_TIMEOUT: Duration = Duration::from_secs(300);
/// How long a typed key is held, and the pause after it.
const KEY_HOLD: Duration = Duration::from_millis(5);
/// How long a chord from `key` is held.
const CHORD_HOLD: Duration = Duration::from_millis(50);
/// Pause between the clicks of a double click and the steps of a drag.
const POINTER_STEP: Duration = Duration::from_millis(20);
/// Time for the guest to draw the result of a click before the screenshot.
const CLICK_SETTLE: Duration = Duration::from_millis(50);
const DRAG_STEPS: u32 = 10;
/// How long an input action waits for the one before it.
const INPUT_BUSY_WAIT: Duration = Duration::from_secs(30);
/// Most wheel clicks in one scroll.
const MAX_SCROLL: u32 = 50;

/// A pointer button.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Button {
    Left,
    Right,
    Middle,
}

/// A screenshot as PNG, with the size from its header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Screenshot {
    pub png: Vec<u8>,
    pub width: u32,
    pub height: u32,
}

/// What a new VM looks like.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewVm {
    pub name: String,
    pub image: String,
    pub vcpus: u32,
    pub memory_mib: u64,
    pub disk_gib: u64,
    pub net: NetProfile,
    /// Agents may control it from the start (only for VMs agents create).
    pub agent_control: bool,
}

/// A running QEMU process.
pub struct Running {
    pub config: VmConfig,
    pub pid: u32,
    pub qmp: Qmp,
    qga_sock: PathBuf,
    rt_dir: PathBuf,
    /// One screendump at a time (they share files).
    screen_lock: tokio::sync::Mutex<()>,
    /// One input action at a time, so typed text never interleaves.
    input_lock: tokio::sync::Mutex<()>,
    /// Screen size from the last screenshot; pointer coordinates use it.
    screen_size: Mutex<(u32, u32)>,
    /// One guest-agent operation at a time.
    /// The guest-agent connection, kept between operations (the agent
    /// sleeps ~100 ms after every disconnect), one operation at a time.
    qga: tokio::sync::Mutex<Option<Qga>>,
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
        ensure_private_dir(&self.paths.audit_dir())?;
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
            agent_control: new.agent_control,
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
        // QEMU may only overwrite these (confine.rs), never create files.
        for f in qemu::SCREEN_FILES {
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(rt_dir.join(f))?;
        }
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
            rt_dir: rt_dir.clone(),
            screen_lock: tokio::sync::Mutex::new(()),
            input_lock: tokio::sync::Mutex::new(()),
            screen_size: Mutex::new(qemu::SCREEN),
            qga: tokio::sync::Mutex::new(None),
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

    /// The guest's IP addresses (from the guest agent; `None` if it is busy
    /// or does not answer) and the disk space the VM's disk uses on the host.
    pub async fn details(&self, name: &str) -> Result<(Option<Vec<(String, String)>>, u64)> {
        use std::os::unix::fs::MetadataExt;
        self.check_exists(name)?;
        let disk =
            fs::metadata(self.paths.vm_dir(name).join(qemu::DISK)).map_or(0, |m| m.blocks() * 512);
        let ips = match self.running(name) {
            // Not behind a long exec: ask only if the agent is free.
            Some(vm) => vm.addresses().await.ok(),
            None => Some(Vec::new()),
        };
        Ok((ips, disk))
    }

    /// Resets the VM like a hardware reset button.
    pub async fn reset(&self, name: &str) -> Result<()> {
        self.running_vm(name)?
            .qmp
            .execute("system_reset", None)
            .await?;
        Ok(())
    }

    /// Turns agent control of a VM on or off (stored in `vm.toml`).
    pub async fn set_agent(&self, name: &str, on: bool) -> Result<()> {
        self.check_exists(name)?;
        let _op = self.lock(name).await;
        let mut cfg = self.load(name)?;
        cfg.agent_control = on;
        cfg.save(&self.paths.vm_dir(name))
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

    fn running_vm(&self, name: &str) -> Result<Arc<Running>> {
        self.check_exists(name)?;
        self.running(name)
            .with_context(|| format!("{name} is not running; start it with `stallo start {name}`"))
    }

    /// The guest screen as PNG.
    pub async fn screenshot(&self, name: &str) -> Result<Screenshot> {
        self.running_vm(name)?.screenshot().await
    }

    /// Waits until the screen has not changed for `stable`, at most
    /// `limit`, and returns it. `false` means it never settled; the last
    /// screen is returned anyway.
    pub async fn wait_for_screen(
        &self,
        name: &str,
        stable: Duration,
        limit: Duration,
    ) -> Result<(Screenshot, bool)> {
        ensure!(
            (SCREEN_POLL..=Duration::from_secs(60)).contains(&stable),
            "stable_ms must be between 250 and 60000"
        );
        ensure!(
            (stable..=SCREEN_MAX_TIMEOUT).contains(&limit),
            "timeout_ms must be between stable_ms and 300000"
        );
        // The returned PNG is taken after the screen settled; on a screen
        // that keeps changing it can differ from the last compared frame.
        let vm = self.running_vm(name)?;
        let settled = settle(|| vm.screendump("screen.ppm", "ppm"), stable, limit).await?;
        Ok((vm.screenshot().await?, settled))
    }

    /// Moves the pointer to pixel (`x`, `y`) of the last screenshot.
    pub async fn mouse_move(&self, name: &str, x: u32, y: u32) -> Result<()> {
        self.running_vm(name)?.mouse_move(x, y).await
    }

    /// Clicks at (`x`, `y`); with `screenshot`, returns the screen shortly
    /// after.
    pub async fn click(
        &self,
        name: &str,
        (x, y): (u32, u32),
        button: Button,
        double: bool,
        screenshot: bool,
    ) -> Result<Option<Screenshot>> {
        let vm = self.running_vm(name)?;
        vm.click((x, y), button, double, screenshot).await
    }

    /// Presses the left button at `from`, moves to `to` in steps, releases.
    pub async fn drag(&self, name: &str, from: (u32, u32), to: (u32, u32)) -> Result<()> {
        self.running_vm(name)?.drag(from, to).await
    }

    /// Scrolls at (`x`, `y`): `dy` wheel clicks, positive is down.
    pub async fn scroll(&self, name: &str, x: u32, y: u32, dy: i32) -> Result<()> {
        self.running_vm(name)?.scroll((x, y), dy).await
    }

    /// Types `text` on a US keyboard layout.
    pub async fn type_text(&self, name: &str, text: &str) -> Result<()> {
        let keys = input::text_keys(text)?;
        self.running_vm(name)?.type_keys(&keys).await
    }

    /// Presses a chord such as `ctrl+alt+t`.
    pub async fn key(&self, name: &str, chord: &str) -> Result<()> {
        let keys = input::chord(chord)?;
        let vm = self.running_vm(name)?;
        let _input = vm.input().await?;
        vm.send_key(&keys, CHORD_HOLD).await
    }

    /// Runs `argv` in the guest with `stdin` as its input. Without `admin`
    /// it runs as the guest user. Only one guest command runs per VM at a
    /// time.
    pub async fn exec(
        &self,
        name: &str,
        argv: &[String],
        admin: bool,
        limit: Duration,
        stdin: Option<&[u8]>,
    ) -> Result<ExecOutput> {
        ensure!(!argv.is_empty(), "nothing to run");
        ensure!(
            limit >= Duration::from_secs(1),
            "timeout must be at least 1 s"
        );
        ensure!(
            limit <= EXEC_MAX_TIMEOUT,
            "timeout is at most {EXEC_MAX_TIMEOUT:?}"
        );
        self.run_guest(name, argv, admin, limit, EXEC_OUTPUT_CAP, stdin)
            .await
    }

    async fn run_guest(
        &self,
        name: &str,
        argv: &[String],
        admin: bool,
        limit: Duration,
        cap: usize,
        stdin: Option<&[u8]>,
    ) -> Result<ExecOutput> {
        let vm = self.running_vm(name)?;
        let (path, args) = guest_command(argv, admin, limit);
        let started = Instant::now();
        let out = vm
            .with_agent(QGA_BUSY_WAIT, Duration::from_secs(5), async |q| {
                q.exec(&path, &args, stdin, limit, cap).await
            })
            .await?;
        // The scope's SIGKILL shows up as signal 9.
        ensure!(
            !(out.exit_code == 137 && started.elapsed() >= limit),
            "command timed out after {limit:?} and was killed"
        );
        Ok(out)
    }

    /// Reads up to `max` bytes of the guest file `path` from `offset`, as the
    /// guest user unless `admin`. Returns the bytes and whether the file
    /// goes on.
    pub async fn file_read(
        &self,
        name: &str,
        path: &str,
        offset: u64,
        max: usize,
        admin: bool,
    ) -> Result<(Vec<u8>, bool)> {
        ensure!(
            (1..=FILE_MAX).contains(&max),
            "max_bytes must be between 1 and {FILE_MAX}"
        );
        let argv = file_read_argv(path, offset, max)?;
        let out = self
            .run_guest(name, &argv, admin, FILE_TIMEOUT, max + 1, None)
            .await?;
        file_status(&out, "read", path)?;
        Ok(split_more(out.stdout, max))
    }

    /// Writes `data` to the guest file `path` (replacing it, or appending),
    /// as the guest user unless `admin`.
    pub async fn file_write(
        &self,
        name: &str,
        path: &str,
        data: &[u8],
        append: bool,
        admin: bool,
    ) -> Result<()> {
        ensure!(
            data.len() <= FILE_MAX,
            "at most {FILE_MAX} bytes per write; append the rest"
        );
        let argv = file_write_argv(path, append)?;
        let out = self
            .run_guest(name, &argv, admin, FILE_TIMEOUT, 4096, Some(data))
            .await?;
        file_status(&out, "write", path)
    }
}

impl Running {
    /// Takes the input lock (waiting a bounded time) and checks that the
    /// guest runs: input into a paused VM would be lost without an error.
    async fn input(&self) -> Result<tokio::sync::MutexGuard<'_, ()>> {
        let guard = tokio::time::timeout(INPUT_BUSY_WAIT, self.input_lock.lock())
            .await
            .map_err(|_| anyhow::anyhow!("{} is busy with other input", self.config.name))?;
        let status = self.status().await?;
        ensure!(
            status == "running",
            "{} is {status}; input would be lost",
            self.config.name
        );
        Ok(guard)
    }

    async fn mouse_move(&self, x: u32, y: u32) -> Result<()> {
        let _input = self.input().await?;
        self.send_events(self.move_events(x, y)?).await
    }

    async fn click(
        &self,
        (x, y): (u32, u32),
        button: Button,
        double: bool,
        screenshot: bool,
    ) -> Result<Option<Screenshot>> {
        let _input = self.input().await?;
        self.send_events(self.move_events(x, y)?).await?;
        for i in 0..if double { 2 } else { 1 } {
            if i > 0 {
                tokio::time::sleep(POINTER_STEP).await;
            }
            self.press_release(button_name(button)).await?;
        }
        if !screenshot {
            return Ok(None);
        }
        // Still holding the input lock: no other input between the click
        // and its screenshot.
        tokio::time::sleep(CLICK_SETTLE).await;
        Ok(Some(self.screenshot().await?))
    }

    async fn drag(&self, from: (u32, u32), to: (u32, u32)) -> Result<()> {
        let _input = self.input().await?;
        // Check both ends before pressing anything.
        self.move_events(to.0, to.1)?;
        self.send_events(self.move_events(from.0, from.1)?).await?;
        let pressed = self.send_events(vec![btn("left", true)]).await;
        let result = async {
            pressed?;
            for step in 1..=DRAG_STEPS {
                tokio::time::sleep(POINTER_STEP).await;
                let x = lerp(from.0, to.0, step, DRAG_STEPS);
                let y = lerp(from.1, to.1, step, DRAG_STEPS);
                self.send_events(self.move_events(x, y)?).await?;
            }
            Ok::<_, anyhow::Error>(())
        }
        .await;
        // Never leave the button down.
        let released = self.send_events(vec![btn("left", false)]).await;
        result.and(released)
    }

    async fn scroll(&self, (x, y): (u32, u32), dy: i32) -> Result<()> {
        ensure!(
            dy != 0 && dy.unsigned_abs() <= MAX_SCROLL,
            "dy must be between -{MAX_SCROLL} and {MAX_SCROLL}, and not 0"
        );
        let _input = self.input().await?;
        self.send_events(self.move_events(x, y)?).await?;
        let wheel = if dy > 0 { "wheel-down" } else { "wheel-up" };
        for _ in 0..dy.unsigned_abs() {
            self.press_release(wheel).await?;
        }
        Ok(())
    }

    async fn type_keys(&self, keys: &[Vec<&str>]) -> Result<()> {
        let _input = self.input().await?;
        for k in keys {
            self.send_key(k, KEY_HOLD).await?;
        }
        Ok(())
    }

    /// Presses and releases a button in separate frames, as a real mouse
    /// does. The release is sent even if the press failed.
    async fn press_release(&self, button: &str) -> Result<()> {
        let pressed = self.send_events(vec![btn(button, true)]).await;
        let released = self.send_events(vec![btn(button, false)]).await;
        pressed.and(released)
    }

    async fn screenshot(&self) -> Result<Screenshot> {
        let png = self.screendump("screen.png", "png").await?;
        let (width, height) = input::png_size(&png)?;
        *self.screen_size.lock().unwrap() = (width, height);
        Ok(Screenshot { png, width, height })
    }

    /// Absolute pointer events for pixel (`x`, `y`) of the last screenshot.
    fn move_events(&self, x: u32, y: u32) -> Result<Vec<Value>> {
        let (w, h) = *self.screen_size.lock().unwrap();
        let axis = |name: &str, v: u32| serde_json::json!({"type": "abs", "data": {"axis": name, "value": v}});
        Ok(vec![
            axis("x", input::abs_axis(x, w)?),
            axis("y", input::abs_axis(y, h)?),
        ])
    }

    async fn send_events(&self, events: Vec<Value>) -> Result<()> {
        self.qmp
            .execute(
                "input-send-event",
                Some(serde_json::json!({"events": events})),
            )
            .await?;
        Ok(())
    }

    /// Presses `keys` together, holds them for `hold` and releases them in
    /// reverse order. Sent as plain input events (not `send-key`, whose
    /// internal queue silently drops keys when typing is fast) and paced
    /// here, so the guest sees every key.
    async fn send_key(&self, keys: &[&str], hold: Duration) -> Result<()> {
        let event = |k: &str, down: bool| {
            serde_json::json!({"type": "key", "data": {"down": down,
                "key": {"type": "qcode", "data": k}}})
        };
        let pressed = self
            .send_events(keys.iter().map(|k| event(k, true)).collect())
            .await;
        tokio::time::sleep(hold).await;
        // Released even if the press failed: never leave a modifier down.
        let released = self
            .send_events(keys.iter().rev().map(|k| event(k, false)).collect())
            .await;
        tokio::time::sleep(hold).await;
        pressed.and(released)
    }

    /// Has QEMU write the screen to `<rt>/<file>` and reads it back.
    async fn screendump(&self, file: &str, format: &str) -> Result<Vec<u8>> {
        let _screen = self.screen_lock.lock().await;
        let _slot = SCREENS.acquire().await?;
        let path = self.rt_dir.join(file);
        self.qmp
            .execute(
                "screendump",
                Some(serde_json::json!({"filename": path, "format": format})),
            )
            .await
            .context("cannot take a screenshot")?;
        // Off the async workers: a read of up to MAX_SCREEN_BYTES.
        tokio::task::spawn_blocking(move || take_capped(&path, MAX_SCREEN_BYTES)).await?
    }

    /// Runs `op` on the guest-agent connection: the kept one after a quick
    /// re-sync, or a new one, all within `connect`. Waits at most `busy`
    /// for an operation before it. A failed operation drops the connection
    /// (it may be out of step with the agent).
    async fn with_agent<T>(
        &self,
        busy: Duration,
        connect: Duration,
        op: impl AsyncFnOnce(&mut Qga) -> Result<T>,
    ) -> Result<T> {
        let mut agent = tokio::time::timeout(busy, self.qga.lock())
            .await
            .map_err(|_| {
                anyhow::anyhow!("{} is busy with another guest command", self.config.name)
            })?;
        let ready = tokio::time::timeout(connect, async {
            if let Some(q) = agent.as_mut()
                && q.resync(connect).await.is_err()
            {
                *agent = None;
            }
            if agent.is_none() {
                *agent = Some(Qga::connect(&self.qga_sock, connect).await?);
            }
            Ok::<_, anyhow::Error>(())
        })
        .await;
        match ready {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                *agent = None;
                bail!("guest agent did not answer within {connect:?}");
            }
        }
        let q = agent.as_mut().context("no guest agent connection")?;
        let result = op(q).await;
        if result.is_err() {
            *agent = None;
        }
        result
    }

    async fn addresses(&self) -> Result<Vec<(String, String)>> {
        // Only if the agent is free: never behind a long exec.
        self.with_agent(
            Duration::from_millis(100),
            Duration::from_secs(2),
            async |q| q.addresses().await,
        )
        .await
    }

    async fn ping(&self) -> Result<()> {
        self.with_agent(QGA_BUSY_WAIT, Duration::from_secs(2), async |q| {
            q.ping().await
        })
        .await
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

/// Reads a file that untrusted QEMU wrote, then empties it (it lives on
/// tmpfs, in RAM): never follows a link, never blocks on a FIFO, accepts
/// only a regular file of at most `cap` bytes.
fn take_capped(path: &Path, cap: u64) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("cannot open {}", path.display()))?;
    let meta = f.metadata()?;
    ensure!(meta.is_file(), "{} is not a file", path.display());
    let mut data = Vec::with_capacity(meta.len().min(cap) as usize + 1);
    (&mut f).take(cap + 1).read_to_end(&mut data)?;
    f.set_len(0)?;
    ensure!(
        data.len() as u64 <= cap,
        "screenshot is larger than {cap} bytes"
    );
    Ok(data)
}

/// Pixels that may change between "equal" frames: a blinking text cursor
/// (a block of up to 16x32 pixels) must not keep a screen unsettled.
// ponytail: fixed threshold; make it a parameter if GUIs with animations
// need more.
const FLICKER_PIXELS: usize = 1024;

/// Whether two PPM frames differ in at most [`FLICKER_PIXELS`] pixels.
fn nearly_equal(a: &[u8], b: &[u8]) -> bool {
    if a == b {
        return true;
    }
    let (Some(a), Some(b)) = (ppm_pixels(a), ppm_pixels(b)) else {
        return false;
    };
    a.len() == b.len()
        && a.chunks(3)
            .zip(b.chunks(3))
            .filter(|(x, y)| x != y)
            .take(FLICKER_PIXELS + 1)
            .count()
            <= FLICKER_PIXELS
}

/// The pixel bytes of a PPM: after "P6", width, height and maxval, each
/// followed by a newline (as QEMU writes it).
fn ppm_pixels(f: &[u8]) -> Option<&[u8]> {
    let mut newlines = f.iter().enumerate().filter(|(_, b)| **b == b'\n');
    newlines.nth(2).map(|(i, _)| &f[i + 1..])
}

/// Polls `frame` (250 ms between frames) until the frames stay nearly equal
/// to one reference frame for `stable` (true) or `limit` passes (false).
/// A blinking cursor is ignored; slow changes add up against the reference.
async fn settle<F, Fut>(mut frame: F, stable: Duration, limit: Duration) -> Result<bool>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<Vec<u8>>>,
{
    use tokio::time::Instant;
    let started = Instant::now();
    let mut reference = frame().await?;
    let mut since = Instant::now();
    loop {
        if since.elapsed() >= stable {
            return Ok(true);
        }
        if started.elapsed() >= limit {
            return Ok(false);
        }
        tokio::time::sleep(SCREEN_POLL).await;
        let next = frame().await?;
        if !nearly_equal(&next, &reference) {
            reference = next;
            since = Instant::now();
        }
    }
}

/// The point `step / steps` of the way from `a` to `b`.
fn lerp(a: u32, b: u32, step: u32, steps: u32) -> u32 {
    let (a, b) = (i64::from(a), i64::from(b));
    (a + (b - a) * i64::from(step) / i64::from(steps)) as u32
}

fn button_name(b: Button) -> &'static str {
    match b {
        Button::Left => "left",
        Button::Right => "right",
        Button::Middle => "middle",
    }
}

fn btn(button: &str, down: bool) -> Value {
    serde_json::json!({"type": "btn", "data": {"button": button, "down": down}})
}

/// Checks a guest path: absolute, no NUL (QGA passes C strings), bounded.
fn check_guest_path(path: &str) -> Result<()> {
    ensure!(path.len() <= 4096, "guest path is longer than 4096 bytes");
    ensure!(!path.contains('\0'), "guest path contains a NUL byte");
    ensure!(
        path.starts_with('/'),
        "guest path must be absolute: {path:?}"
    );
    Ok(())
}

/// `dd` reads `max + 1` bytes from `offset`, so the caller sees whether
/// the file goes on. One program, no shell: the path is a single argument.
fn file_read_argv(path: &str, offset: u64, max: usize) -> Result<Vec<String>> {
    check_guest_path(path)?;
    Ok(vec![
        "dd".into(),
        format!("if={path}"),
        "bs=4M".into(),
        "iflag=skip_bytes,count_bytes,fullblock".into(),
        format!("skip={offset}"),
        format!("count={}", max + 1),
        "status=none".into(),
    ])
}

/// `dd` writes its stdin to `path`, truncating it unless `append`.
fn file_write_argv(path: &str, append: bool) -> Result<Vec<String>> {
    check_guest_path(path)?;
    let mut argv = vec!["dd".into(), format!("of={path}"), "bs=4M".into()];
    if append {
        argv.extend(["oflag=append".into(), "conv=notrunc".into()]);
    }
    argv.push("status=none".into());
    Ok(argv)
}

/// `max + 1` bytes were asked for: whether the file goes on, and the
/// data cut to `max`.
fn split_more(mut data: Vec<u8>, max: usize) -> (Vec<u8>, bool) {
    let more = data.len() > max;
    data.truncate(max);
    (data, more)
}

/// Turns a failed `dd` into "cannot read <path>: <its last error line>".
/// The line comes from the guest: control characters are dropped and it is
/// cut to 200 characters.
fn file_status(out: &ExecOutput, what: &str, path: &str) -> Result<()> {
    if out.exit_code == 0 {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    let last = stderr.lines().rev().find(|l| !l.trim().is_empty());
    let reason: String = last
        .unwrap_or("failed")
        .trim_start_matches("dd: ")
        .chars()
        .filter(|c| !c.is_control())
        .take(200)
        .collect();
    bail!("cannot {what} {}: {reason}", path.escape_debug())
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

    /// A 64x64 PPM filled with `fill`, with the first `marked` pixels white.
    fn ppm(fill: u8, marked: usize) -> Vec<u8> {
        let mut f = b"P6\n64 64\n255\n".to_vec();
        let start = f.len();
        f.resize(start + 3 * 4096, fill);
        f[start..start + 3 * marked].fill(255);
        f
    }

    #[tokio::test(start_paused = true)]
    async fn screen_settles_or_times_out() {
        use tokio::time::Instant;
        let ms = Duration::from_millis;
        // Changes for the first 4 frames (1 s), then stays the same.
        let mut n = 0u8;
        let changing_then_still = || {
            n += 1;
            let frame = ppm(n.min(4), 0);
            async move { Ok(frame) }
        };
        let t = Instant::now();
        assert!(
            settle(changing_then_still, ms(1000), ms(5000))
                .await
                .unwrap()
        );
        assert!(
            (ms(1750)..=ms(2250)).contains(&t.elapsed()),
            "{:?}",
            t.elapsed()
        );

        let mut n = 0u8;
        let always_changing = || {
            n = n.wrapping_add(1);
            let frame = ppm(n, 0);
            async move { Ok(frame) }
        };
        let t = Instant::now();
        assert!(!settle(always_changing, ms(1000), ms(3000)).await.unwrap());
        assert!(t.elapsed() <= ms(3250));

        let failing = || async { Err(anyhow::anyhow!("gone")) };
        assert!(settle(failing, ms(1000), ms(3000)).await.is_err());

        // A blinking cursor (a few pixels toggling) counts as settled.
        let mut n = 0usize;
        let blinking = || {
            n += 1;
            let frame = ppm(0, if n.is_multiple_of(2) { 100 } else { 0 });
            async move { Ok(frame) }
        };
        assert!(settle(blinking, ms(1000), ms(3000)).await.unwrap());

        // Small steps that add up (slow output) are not settled.
        let mut n = 0usize;
        let creeping = || {
            n += 1;
            let frame = ppm(0, (n * 300).min(4096));
            async move { Ok(frame) }
        };
        assert!(!settle(creeping, ms(1000), ms(3000)).await.unwrap());
    }

    #[test]
    fn flicker_threshold() {
        let a = ppm(0, 0);
        assert!(nearly_equal(&a, &ppm(0, FLICKER_PIXELS)));
        assert!(!nearly_equal(&a, &ppm(0, FLICKER_PIXELS + 1)));
        assert!(!nearly_equal(&a, &a[..20]));
        assert!(!nearly_equal(b"junk", b"junk2"));
        assert!(nearly_equal(b"same", b"same"));
        assert_eq!(ppm_pixels(&a).unwrap().len(), 3 * 4096);
    }

    #[test]
    fn untrusted_screen_files() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("screen.png");
        fs::write(&file, b"png").unwrap();
        assert_eq!(take_capped(&file, 3).unwrap(), b"png");
        assert_eq!(
            fs::metadata(&file).unwrap().len(),
            0,
            "emptied after reading"
        );
        fs::write(&file, b"png!").unwrap();
        assert!(take_capped(&file, 3).is_err());

        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(take_capped(&link, 3).is_err());
        let fifo = dir.path().join("fifo");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        assert!(
            take_capped(&fifo, 3).is_err(),
            "a FIFO neither blocks nor passes"
        );
        let sock = dir.path().join("sock");
        let _l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        assert!(take_capped(&sock, 3).is_err());
        assert!(take_capped(dir.path(), 3).is_err());
    }

    /// A fake QEMU that records commands, reports `status` and fails the
    /// `fail_at`th `input-send-event` (1-based).
    async fn fake_vm(
        status: &'static str,
        fail_at: Option<usize>,
    ) -> (tempfile::TempDir, Running, Arc<Mutex<Vec<Value>>>) {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("qmp.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let log = Arc::new(Mutex::new(Vec::new()));
        let seen = log.clone();
        tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            let (r, mut w) = s.into_split();
            let mut lines = BufReader::new(r).lines();
            w.write_all(b"{\"QMP\": {\"version\": {}, \"capabilities\": []}}\n")
                .await
                .unwrap();
            let mut events = 0;
            while let Ok(Some(line)) = lines.next_line().await {
                let req: Value = serde_json::from_str(&line).unwrap();
                let reply = match req["execute"].as_str().unwrap() {
                    "query-status" => serde_json::json!({"return": {"status": status}}),
                    "input-send-event" => {
                        events += 1;
                        seen.lock()
                            .unwrap()
                            .push(req["arguments"]["events"].clone());
                        if Some(events) == fail_at {
                            serde_json::json!({"error": {"class": "GenericError", "desc": "x"}})
                        } else {
                            serde_json::json!({"return": {}})
                        }
                    }
                    _ => serde_json::json!({"return": {}}),
                };
                let mut reply = reply;
                if let Some(id) = req.get("id") {
                    reply["id"] = id.clone();
                }
                w.write_all(format!("{reply}\n").as_bytes()).await.unwrap();
            }
        });
        let qmp = Qmp::connect(&path, Duration::from_secs(5)).await.unwrap();
        let (_tx, exited) = watch::channel(false);
        let vm = Running {
            config: VmConfig {
                name: "dev".into(),
                uuid: "4f1c2b9e-0d3a-4c5e-8f7a-1b2c3d4e5f60".into(),
                image: "ubuntu-26.04".into(),
                vcpus: 1,
                memory_mib: 512,
                disk_gib: 10,
                net: NetProfile::Offline,
                agent_control: false,
            },
            pid: 0,
            qmp,
            qga_sock: dir.path().join("qga.sock"),
            rt_dir: "/nonexistent".into(),
            screen_lock: tokio::sync::Mutex::new(()),
            input_lock: tokio::sync::Mutex::new(()),
            screen_size: Mutex::new(qemu::SCREEN),
            qga: tokio::sync::Mutex::new(None),
            disk_full: AtomicBool::new(false),
            exited,
        };
        (dir, vm, log)
    }

    /// The recorded events as compact strings, e.g. `btn left 1`.
    fn summary(log: &Mutex<Vec<Value>>) -> Vec<String> {
        log.lock()
            .unwrap()
            .iter()
            .map(|events| {
                events
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|e| {
                        let d = &e["data"];
                        match e["type"].as_str().unwrap() {
                            "abs" => format!("{}={}", d["axis"].as_str().unwrap(), d["value"]),
                            "btn" => format!("btn {} {}", d["button"].as_str().unwrap(), d["down"]),
                            "key" => {
                                format!("key {} {}", d["key"]["data"].as_str().unwrap(), d["down"])
                            }
                            t => panic!("{t}"),
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .collect()
    }

    #[tokio::test]
    async fn input_events() {
        let (_d, vm, log) = fake_vm("running", None).await;
        vm.click((640, 400), Button::Right, true, false)
            .await
            .unwrap();
        let (x, y) = (
            input::abs_axis(640, 1280).unwrap(),
            input::abs_axis(400, 800).unwrap(),
        );
        assert_eq!(
            summary(&log),
            [
                format!("x={x} y={y}"),
                "btn right true".into(),
                "btn right false".into(),
                "btn right true".into(),
                "btn right false".into(),
            ]
        );
        log.lock().unwrap().clear();
        vm.scroll((0, 0), -2).await.unwrap();
        assert_eq!(
            summary(&log)[1..],
            [
                "btn wheel-up true",
                "btn wheel-up false",
                "btn wheel-up true",
                "btn wheel-up false"
            ]
        );
        assert!(vm.scroll((0, 0), 51).await.is_err());
        log.lock().unwrap().clear();
        vm.send_key(&input::chord("ctrl+c").unwrap(), Duration::ZERO)
            .await
            .unwrap();
        assert_eq!(
            summary(&log),
            ["key ctrl true key c true", "key c false key ctrl false"]
        );
        log.lock().unwrap().clear();
        assert!(vm.drag((0, 0), (0, 800)).await.is_err());
        assert!(summary(&log).is_empty(), "nothing pressed for a bad drag");
    }

    /// A fake guest agent that counts connections and answers sync and
    /// ping; it hangs up after `hang_up_after` replies on a connection.
    fn fake_agent(path: &Path, hang_up_after: usize) -> Arc<std::sync::atomic::AtomicUsize> {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let listener = tokio::net::UnixListener::bind(path).unwrap();
        let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = accepted.clone();
        tokio::spawn(async move {
            while let Ok((s, _)) = listener.accept().await {
                count.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let (r, mut w) = s.into_split();
                    let mut lines = BufReader::new(r).split(b'\n');
                    for _ in 0..hang_up_after {
                        let Ok(Some(line)) = lines.next_segment().await else {
                            return;
                        };
                        let req: Value =
                            serde_json::from_slice(line.strip_prefix(&[0xFF]).unwrap_or(&line))
                                .unwrap();
                        let bytes = if req["execute"] == "guest-sync-delimited" {
                            let id = &req["arguments"]["id"];
                            [&[0xFF][..], format!("{{\"return\": {id}}}\n").as_bytes()].concat()
                        } else {
                            b"{\"return\": {}}\n".to_vec()
                        };
                        if w.write_all(&bytes).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        accepted
    }

    const WAIT_AGENT: Duration = Duration::from_secs(2);

    #[tokio::test]
    async fn guest_agent_connection_is_kept() {
        let (_d, vm, _) = fake_vm("running", None).await;
        let accepted = fake_agent(&vm.qga_sock, usize::MAX);
        for _ in 0..3 {
            vm.ping().await.unwrap();
        }
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            1,
            "one connection for three pings"
        );

        // A failed operation drops the connection; the next use reconnects.
        let failed: Result<()> = vm
            .with_agent(QGA_BUSY_WAIT, WAIT_AGENT, async |_| bail!("broken"))
            .await;
        assert!(failed.is_err());
        vm.ping().await.unwrap();
        assert_eq!(accepted.load(Ordering::SeqCst), 2);

        // An agent that hangs up is reconnected on the next use.
        let (_d, vm, _) = fake_vm("running", None).await;
        let accepted = fake_agent(&vm.qga_sock, 2);
        vm.ping().await.unwrap();
        vm.ping().await.unwrap();
        assert_eq!(accepted.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn releases_after_errors() {
        // The press fails: the release is still sent.
        let (_d, vm, log) = fake_vm("running", Some(1)).await;
        assert!(vm.send_key(&["shift", "a"], Duration::ZERO).await.is_err());
        assert_eq!(summary(&log)[1], "key a false key shift false");
        // A drag step fails: the button is still released.
        let (_d, vm, log) = fake_vm("running", Some(3)).await;
        assert!(vm.drag((0, 0), (10, 10)).await.is_err());
        assert_eq!(summary(&log).last().unwrap(), "btn left false");
        // The second click of a double click fails to press.
        let (_d, vm, log) = fake_vm("running", Some(4)).await;
        assert!(vm.click((1, 1), Button::Left, true, false).await.is_err());
        assert_eq!(summary(&log).last().unwrap(), "btn left false");
    }

    #[tokio::test]
    async fn no_input_into_a_paused_vm() {
        let (_d, vm, log) = fake_vm("paused", None).await;
        let err = vm.type_keys(&[vec!["a"]]).await.unwrap_err();
        assert!(err.to_string().contains("paused"), "{err}");
        assert!(vm.mouse_move(1, 1).await.is_err());
        assert!(log.lock().unwrap().is_empty());
    }

    #[test]
    fn file_commands() {
        assert_eq!(
            file_read_argv("/etc/a b", 5, 10).unwrap().join(" "),
            "dd if=/etc/a b bs=4M iflag=skip_bytes,count_bytes,fullblock skip=5 count=11 status=none"
        );
        assert_eq!(
            file_write_argv("/tmp/x", false).unwrap().join(" "),
            "dd of=/tmp/x bs=4M status=none"
        );
        assert_eq!(
            file_write_argv("/tmp/x", true).unwrap().join(" "),
            "dd of=/tmp/x bs=4M oflag=append conv=notrunc status=none"
        );
        for bad in ["relative", "", "/a\0b", &format!("/{}", "a".repeat(4096))] {
            assert!(file_read_argv(bad, 0, 1).is_err(), "{bad:?}");
            assert!(file_write_argv(bad, false).is_err(), "{bad:?}");
        }
        let failed = ExecOutput {
            exit_code: 1,
            stdout: Vec::new(),
            stderr: b"dd: failed to open '/x': Permission denied\n".to_vec(),
            truncated: false,
        };
        let err = file_status(&failed, "read", "/x").unwrap_err().to_string();
        assert_eq!(
            err,
            "cannot read /x: failed to open '/x': Permission denied"
        );
    }

    #[test]
    fn drag_path() {
        assert_eq!(lerp(0, 1279, 0, 10), 0);
        assert_eq!(lerp(0, 1279, 5, 10), 639);
        assert_eq!(lerp(0, 1279, 10, 10), 1279);
        assert_eq!(lerp(100, 0, 10, 10), 0);
        assert_eq!(lerp(100, 0, 3, 10), 70);
    }

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
