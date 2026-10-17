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
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, OpenOptionsExt, PermissionsExt};
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
use crate::config::{
    DaemonConfig, Mode, NetProfile, PortForward, VmConfig, new_uuid, validate_image_id,
    validate_name,
};
use crate::host::{self, Ask, HostInfo};
use crate::paths::{Paths, ensure_private_dir, safe_remove};
use crate::qga::{ExecOutput, Qga};
use crate::qmp::Qmp;
use crate::{confine, images, input, net, qemu, seed, tpm};

/// passt's messages, in the VM directory.
const PASST_LOG: &str = "passt.log";
/// How long after swtpm's exit QEMU's exit may follow and still count as
/// the cause (QEMU closes swtpm's channel as it exits, and its watcher
/// reports it right after).
const SWTPM_GRACE: Duration = Duration::from_secs(2);
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
/// Names of `stallo run` clones start with this; `new` refuses them.
pub const RUN_PREFIX: &str = "run-";
pub(crate) const QGA_BUSY_WAIT: Duration = Duration::from_secs(30);
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
    /// Host ports forwarded into the guest (`internet` only).
    pub forwards: Vec<PortForward>,
    /// Agents may control it from the start (only for VMs agents create).
    pub agent_control: bool,
    /// Download the image if it is not cached (humans only); otherwise
    /// creation needs a pulled image.
    pub may_pull: bool,
    /// A VNC socket from the first start (humans only).
    pub vnc: bool,
}

/// A running QEMU process.
pub struct Running {
    pub config: VmConfig,
    pub pid: u32,
    /// swtpm's pid and whether it has exited (Windows VMs).
    tpm: Option<(u32, Arc<AtomicBool>)>,
    pub qmp: Qmp,
    qga_sock: PathBuf,
    rt_dir: PathBuf,
    /// One screendump at a time (they share files).
    screen_lock: tokio::sync::Mutex<()>,
    /// One input action at a time, so typed text never interleaves.
    input_lock: tokio::sync::Mutex<()>,
    /// Screen size from the last screenshot; pointer coordinates use it.
    screen_size: Mutex<(u32, u32)>,
    /// The guest-agent connection, kept between operations (the agent
    /// sleeps ~100 ms after every disconnect), one operation at a time.
    pub(crate) qga: tokio::sync::Mutex<Option<Qga>>,
    /// Paused by the disk watchdog.
    pub(crate) disk_full: AtomicBool,
    /// Set when passt is gone: cut because the host's isolation went
    /// away, or exited by itself. The guest stays up without network until
    /// it restarts.
    pub(crate) net_down: Arc<AtomicBool>,
    /// Wakes passt's reaper to kill it (`internet` VMs only).
    cut_net: Option<Arc<tokio::sync::Notify>>,
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
    pub mode: Mode,
    cgroups: Cgroups,
    running: Mutex<HashMap<String, Arc<Running>>>,
    /// Per-name lifecycle locks.
    ops: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// Image downloads and removals take it exclusively, one at a time;
    /// VM creation shares it while it builds a disk on an image. Lock
    /// order: a VM's lifecycle lock, then this one. Pulls and removals
    /// take no VM lock.
    pub(crate) images: tokio::sync::RwLock<()>,
    /// Serialises admission: checking what fits and starting it is atomic.
    admission: tokio::sync::Mutex<()>,
    /// VMs whose disk a `stallo run` clone uses; their lifecycle lock is
    /// held until the run ends.
    pub(crate) in_run: Mutex<std::collections::HashSet<String>>,
}

impl Manager {
    pub fn new(paths: Paths, config: DaemonConfig, cgroups: Cgroups, mode: Mode) -> Arc<Self> {
        Arc::new(Self {
            paths,
            config,
            mode,
            cgroups,
            running: Mutex::default(),
            ops: Mutex::default(),
            images: tokio::sync::RwLock::default(),
            admission: tokio::sync::Mutex::default(),
            in_run: Mutex::default(),
        })
    }

    /// File modes for what the daemon shares with API users: in production
    /// group `stallo` (directory, socket), in dev mode nobody else.
    fn shared_modes(&self) -> (u32, u32) {
        match self.mode {
            Mode::Dev => (0o700, 0o600),
            Mode::Production => (0o750, 0o660),
        }
    }

    /// Creates `dir` for API users (see [`Manager::shared_modes`]).
    fn shared_dir(&self, dir: &Path) -> Result<()> {
        ensure_private_dir(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(self.shared_modes().0))?;
        Ok(())
    }

    /// Kills leftovers of an earlier daemon: VM cgroups and runtime dirs,
    /// and the throwaway clones of runs it did not finish.
    pub async fn cleanup_leftovers(&self) -> Result<()> {
        self.cgroups.remove_leftovers().await?;
        safe_remove(&self.paths.runtime, &self.paths.vms_runtime_dir())?;
        ensure_private_dir(&self.paths.vms_runtime_dir())?;
        safe_remove(&self.paths.runtime, &self.paths.vnc_root())?;
        self.shared_dir(&self.paths.vnc_root())?;
        ensure_private_dir(&self.paths.vms_dir())?;
        ensure_private_dir(&self.paths.audit_dir())?;
        // Clones of runs that were cut off, also half-made ones.
        for entry in fs::read_dir(self.paths.vms_dir())? {
            let name = entry?.file_name();
            let Some(name) = name.to_str().filter(|n| n.starts_with(RUN_PREFIX)) else {
                continue;
            };
            tracing::info!("{name}: removing the clone of a cut-off run");
            if let Err(e) = safe_remove(&self.paths.data, &self.paths.vm_dir(name)) {
                tracing::error!("{name}: cannot remove: {e:#}");
            }
        }
        Ok(())
    }

    // ponytail: entries are never removed (removing one would let two
    // callers hold different locks for one name); the map grows by the
    // number of distinct VM names ever used (each `stallo run` adds its
    // clone's name).
    //
    // A VM that a `stallo run` uses (its source or its clone) is refused at
    // once instead: the run holds its lock for as long as its command runs.
    // (A caller already queued for the lock before the run took it still
    // waits for the run.)
    pub(crate) async fn lock(&self, name: &str) -> Result<tokio::sync::OwnedMutexGuard<()>> {
        let lock = self.op_lock(name);
        {
            // Checked together with the run's take-and-mark (`lock_for_run`).
            let in_run = self.in_run.lock().unwrap();
            if let Ok(guard) = lock.clone().try_lock_owned() {
                return Ok(guard);
            }
            ensure!(
                !in_run.contains(name),
                "{name} is in use by `stallo run`; try again when it ends"
            );
        }
        Ok(lock.lock_owned().await)
    }

    /// Takes `name`'s lifecycle lock for a `stallo run` and marks it as in
    /// use, or fails at once if someone else holds it.
    pub(crate) fn lock_for_run(&self, name: &str) -> Result<tokio::sync::OwnedMutexGuard<()>> {
        let lock = self.op_lock(name);
        let mut in_run = self.in_run.lock().unwrap();
        let guard = lock
            .try_lock_owned()
            .map_err(|_| anyhow::anyhow!("{name} is busy; try again"))?;
        in_run.insert(name.to_owned());
        Ok(guard)
    }

    fn op_lock(&self, name: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.ops
            .lock()
            .unwrap()
            .entry(name.to_owned())
            .or_default()
            .clone()
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
    pub(crate) fn check_exists(&self, name: &str) -> Result<()> {
        validate_name(name)?;
        ensure!(
            self.paths.vm_dir(name).exists(),
            "no VM named {name}; see `stallo ls`"
        );
        Ok(())
    }

    /// Downloads and verifies an image unless it is cached. Refused unless
    /// the download fits above the disk floor ([`host::check_pull_space`]).
    pub async fn pull(&self, id: &str) -> Result<()> {
        let entry = images::find(id)?;
        let _guard = self.images.write().await;
        if !images::cached_path(&self.paths, &entry).is_file() {
            let dir = self.paths.images_dir();
            ensure_private_dir(&dir)?;
            host::check_pull_space(
                host::disk_free(&dir)?,
                self.config.host.disk_floor_gib,
                images::pull_reserve(&entry),
                images::resumable_bytes(&self.paths, &entry),
            )?;
        }
        images::pull(&self.paths, &entry).await
    }

    /// Imports an ISO a client streams (`stallo images import`, see
    /// [`images::import`]). Refused unless `size` bytes fit above the disk
    /// floor, and while a pull, removal or other import runs: the client
    /// sets the pace, so nothing queues behind it.
    pub async fn import_iso(
        &self,
        id: &str,
        os: images::Os,
        name: &str,
        size: u64,
        body: &mut (impl tokio::io::AsyncRead + Unpin),
    ) -> Result<images::Pulled> {
        let _guard = self.images.try_write().map_err(|_| {
            anyhow::anyhow!("an image pull or import is in progress; try again when it ends")
        })?;
        let dir = self.paths.images_dir();
        ensure_private_dir(&dir)?;
        host::check_pull_space(
            host::disk_free(&dir)?,
            self.config.host.disk_floor_gib,
            size,
            0,
        )?;
        images::import(&self.paths, id, os, name, size, body).await
    }

    /// Deletes a cached image (`stallo images rm`). Refused while any VM,
    /// stopped or a `stallo run` clone included, was made from it or has it
    /// in its CD-ROM drive: by its `vm.toml` or by its disk's backing file.
    /// A running VM counts with the ISO it started with: an eject in its
    /// `vm.toml` empties the drive only at the next start. Fails closed: a
    /// VM directory whose `vm.toml` or disk cannot be read refuses the
    /// removal.
    pub async fn remove_image(&self, id: &str) -> Result<()> {
        validate_image_id(id)?;
        let _guard = self.images.write().await;
        let file = format!("{id}.qcow2");
        let mut users = vec![];
        for entry in fs::read_dir(self.paths.vms_dir())? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let (dir, name) = (entry.path(), entry.file_name());
            let name = name.to_string_lossy();
            let cfg = VmConfig::load(&dir).with_context(|| {
                format!(
                    "cannot tell whether {name} uses image {id}; if a `stallo run` is in progress, try again when it ends, otherwise remove it first (stallo rm {name}) or move it out of the vms directory"
                )
            })?;
            let by_config = cfg.image == id || cfg.cdrom.as_deref() == Some(id);
            // A disk is written by its QEMU: only its file name counts, and
            // a disk that cannot be read refuses the removal.
            let by_disk = images::backing_file(&dir.join(qemu::DISK))
                .with_context(|| format!("cannot tell whether {name} uses image {id}"))?
                .is_some_and(|b| Path::new(&b).file_name() == Some(file.as_ref()));
            if by_config || by_disk {
                users.push(name.into_owned());
            }
        }
        // Started before an eject: the ISO is still in the live drive.
        for vm in self.all_running() {
            if vm.config.cdrom.as_deref() == Some(id) {
                users.push(vm.config.name.clone());
            }
        }
        users.sort();
        users.dedup();
        ensure!(
            users.is_empty(),
            "image {id} is in use by {}; remove those VMs first (stallo rm)",
            users.join(", ")
        );
        ensure!(
            images::remove(&self.paths, id)?,
            "image {id} is not pulled; see `stallo images`"
        );
        Ok(())
    }

    /// Creates the VM's directory, disk, firmware variables, password and
    /// seed. On failure nothing is left behind.
    ///
    /// A VM from an installer ISO gets a blank disk, the ISO in its CD-ROM
    /// drive, VNC (the install is done by hand) and no seed or password.
    pub async fn create(&self, new: &NewVm) -> Result<VmConfig> {
        validate_name(&new.name)?;
        ensure!(
            !new.name.starts_with(RUN_PREFIX),
            "names starting with {RUN_PREFIX} are kept for `stallo run`"
        );
        let iso = images::is_iso(&new.image)?;
        // The agent gate refuses this already; fail closed here too.
        ensure!(
            !(iso && new.agent_control),
            "agents may not create VMs from installer ISOs"
        );
        let cfg = VmConfig {
            name: new.name.clone(),
            uuid: new_uuid()?,
            image: new.image.clone(),
            vcpus: new.vcpus,
            memory_mib: new.memory_mib,
            disk_gib: new.disk_gib,
            net: new.net,
            agent_control: new.agent_control,
            throwaway_of: None,
            forwards: new.forwards.clone(),
            vnc: new.vnc || iso,
            cdrom: iso.then(|| new.image.clone()),
            machine: images::image_os(&self.paths, &new.image)?,
        };
        cfg.validate()?;
        cfg.check_min_size()?;
        // Refuse early, before downloading or writing anything.
        self.check_net(&cfg)?;
        self.admit(&cfg, cfg.disk_gib << 30)?;
        if new.may_pull && !images::is_local(&cfg.image) {
            self.pull(&cfg.image).await?;
        }

        // Lock order: the VM's lock, then the images lock (see `images`),
        // so a wait for a busy name never holds up pulls and removals.
        let _op = self.lock(&new.name).await?;
        // Held until the VM's files exist, so `images rm` sees them. The
        // image may have been removed since the pull: checked under it.
        let _image = self.images.read().await;
        images::ensure_pulled(&self.paths, &cfg.image)?;
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
        let firmware = vars_firmware(cfg, images::image_firmware(&cfg.image)?);
        if images::is_iso(&cfg.image)? {
            qemu::create_disk(None, &dir.join(qemu::DISK), cfg.disk_gib).await?;
            qemu::create_vars(&dir.join(qemu::VARS), firmware).await?;
            ensure_private_dir(&dir.join(qemu::STATES))?;
            return cfg.save(&dir);
        }
        let entry = images::find(&cfg.image)?;
        let base = images::image_path(&self.paths, &cfg.image);
        let info = images::check_image(&base).await?;
        ensure!(
            cfg.disk_gib << 30 >= info.virtual_size,
            "disk must be at least {} GiB for {}",
            info.virtual_size.div_ceil(1 << 30),
            cfg.image
        );
        qemu::create_disk(Some(&base), &dir.join(qemu::DISK), cfg.disk_gib).await?;
        qemu::create_vars(&dir.join(qemu::VARS), firmware).await?;
        ensure_private_dir(&dir.join(qemu::STATES))?;

        let password = seed::generate_password()?;
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dir.join("secret"))
            .and_then(|mut f| std::io::Write::write_all(&mut f, password.as_bytes()))
            .context("cannot write the VM secret")?;
        let rendered = seed::render(cfg, &seed::hash_password(&password).await?, &entry)?;
        let debs =
            (entry.agent == images::Agent::Deb).then(|| images::debs_dir(&self.paths, &entry.id));
        seed::build_iso(
            &rendered,
            debs.as_deref(),
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
        let _op = self.lock(name).await?;
        self.start_locked(name, false).await
    }

    /// [`Manager::start`] for a caller that holds the VM's lifecycle lock.
    /// With `paused`, the guest's CPUs wait for `cont` (QEMU `-S`).
    pub(crate) async fn start_locked(
        self: &Arc<Self>,
        name: &str,
        paused: bool,
    ) -> Result<Arc<Running>> {
        let cfg = self.load(name)?;
        ensure!(self.running(name).is_none(), "{name} is already running");
        self.check_net(&cfg)?;

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
        // VMs created before snapshots existed have no directory for them.
        ensure_private_dir(&vm_dir.join(qemu::STATES))?;
        tpm::check_no_restore_pending(&vm_dir)?;
        // (swtpm's end, QEMU's end) of a Windows VM's TPM link; swtpm
        // creates the TPM's state at the first start.
        let tpm_link = if cfg.machine.is_linux() {
            None
        } else {
            ensure_private_dir(&vm_dir.join(tpm::DIR))?;
            Some(net::socketpair()?)
        };
        let tpm_fd = tpm_link.as_ref().map(|(_, q)| q.as_raw_fd());
        // (passt's end, QEMU's end) of the guest's network link.
        let link = match cfg.net {
            NetProfile::Internet => Some(net::socketpair()?),
            NetProfile::Offline => None,
        };
        let qemu_fd = link.as_ref().map(|(_, q)| q.as_raw_fd());
        let vnc_dir = self.paths.vnc_root().join(name);
        safe_remove(&self.paths.runtime, &vnc_dir)?;
        if cfg.vnc {
            self.shared_dir(&vnc_dir)?;
        }
        let vnc = cfg.vnc.then(|| self.paths.vnc_socket(name));
        // An image that left the catalog gets no drop-in: on a disk that
        // already booted, the guest agent need not wait for cloud-init.
        let agent = images::find(&cfg.image).map_or(images::Agent::Deb, |e| e.agent);
        let iso = self.cdrom(&cfg)?;
        let media = match &iso {
            Some(iso) => qemu::Media::Cdrom(iso.as_deref()),
            None => qemu::Media::Seed,
        };
        let mut argv = qemu::argv(
            &cfg,
            &vm_dir,
            &rt_dir,
            qemu_fd,
            tpm_fd,
            vnc.as_deref(),
            agent,
            media,
        )?;
        // Production: the guest's CPUs wait until the spawn checks (AppArmor
        // labels, VNC socket, passt, swtpm) have passed, so no guest code
        // runs in a QEMU that is about to be refused.
        let hold = paused || self.mode == Mode::Production;
        if hold {
            argv.push("-S".to_owned());
        }

        // Held until the VM is registered as running, so concurrent starts
        // see each other.
        let _admission = self.admission.lock().await;
        self.admit(&cfg, 0)?;
        // passt would fail to bind a port another VM already forwards.
        for vm in self.all_running() {
            if let Some(f) = vm.config.forwards.iter().find(|f| {
                cfg.forwards
                    .iter()
                    .any(|g| g.host == f.host && g.bind == f.bind)
            }) {
                bail!(
                    "host port {}:{} is already forwarded to {}",
                    f.bind,
                    f.host,
                    vm.config.name
                );
            }
        }
        match self.spawn(&cfg, &argv, link, tpm_link).await {
            Ok(running) if hold && !paused => match running.qmp.execute("cont", None).await {
                Ok(_) => Ok(running),
                Err(e) => {
                    // The reaper (`watch`) cleans up after the kill.
                    let _ = self.cgroups.kill_vm(name);
                    Err(e.context("cannot start the guest's CPUs"))
                }
            },
            Ok(running) => Ok(running),
            Err(e) => {
                // Best effort: the error that matters is `e`.
                let _ = self.cgroups.remove_vm(name).await;
                let _ = safe_remove(&self.paths.runtime, &rt_dir);
                let _ = safe_remove(&self.paths.runtime, &vnc_dir);
                Err(e)
            }
        }
    }

    /// For a VM made from an installer ISO, its CD-ROM drive: the attached
    /// ISO's path, or `None` if empty. `None` for a VM from a cloud image
    /// (or from an image that left the catalog), which has a seed instead.
    /// A Windows VM is always made from an ISO. Fails closed unless the
    /// drive holds a catalog or imported ISO.
    fn cdrom(&self, cfg: &VmConfig) -> Result<Option<Option<PathBuf>>> {
        if cfg.machine.is_linux() && !images::is_iso(&cfg.image).unwrap_or(false) {
            return Ok(None);
        }
        let Some(id) = &cfg.cdrom else {
            return Ok(Some(None));
        };
        ensure!(
            images::is_iso(id)?,
            "{id} in the CD-ROM drive of {} is not an installer ISO",
            cfg.name
        );
        Ok(Some(Some(images::iso_path(&self.paths, id))))
    }

    /// Whether `cfg`'s network profile may start here. Fail closed: the
    /// internet profile needs production mode and a passing isolation
    /// probe (`net::check_isolation`).
    fn check_net(&self, cfg: &VmConfig) -> Result<()> {
        ensure!(
            cfg.machine.is_linux() || cfg.net == NetProfile::Offline,
            "Windows VMs are offline only for now: the internet profile is not verified with Windows yet"
        );
        if cfg.net != NetProfile::Offline {
            ensure!(
                !images::is_local(&cfg.image),
                "VMs from an imported ISO are offline only for now"
            );
            images::find(&cfg.image)?.check_net(cfg.net)?;
        }
        match (cfg.net, self.mode) {
            (NetProfile::Offline, _) => Ok(()),
            // The host's table matches the daemon's user; in dev mode that
            // is the developer, whose traffic it must not touch.
            (NetProfile::Internet, Mode::Dev) => bail!(
                "isolation unavailable: dev mode runs as your own user, so the internet profile needs production mode"
            ),
            (NetProfile::Internet, Mode::Production) => net::check_isolation(),
        }
    }

    async fn spawn(
        self: &Arc<Self>,
        cfg: &VmConfig,
        argv: &[String],
        link: Option<(OwnedFd, OwnedFd)>,
        tpm_link: Option<(OwnedFd, OwnedFd)>,
    ) -> Result<Arc<Running>> {
        let name = &cfg.name;
        let vm_dir = self.paths.vm_dir(name);
        let rt_dir = self.paths.vm_runtime_dir(name);
        let overhead = self.overhead_mib(cfg);
        let limits = Limits {
            memory_max_bytes: (cfg.memory_mib + overhead) << 20,
            vcpus: cfg.vcpus,
        };
        let log_path = vm_dir.join("qemu.log");
        let log = private_log(&log_path)?;
        let cg = self.cgroups.create_vm(name, limits).await?;
        // passt first, in the same cgroup. If anything below fails, the
        // caller kills the cgroup and passt with it.
        let (mut passt, qemu_end) = match link {
            Some((passt_end, qemu_end)) => {
                let log = private_log(&vm_dir.join(PASST_LOG))?;
                (
                    Some(net::spawn_passt(
                        cfg,
                        self.config.net.dns,
                        passt_end,
                        &cg,
                        log,
                    )?),
                    Some(qemu_end),
                )
            }
            None => (None, None),
        };
        // Then swtpm, also in the cgroup, so it dies with the VM.
        let (mut swtpm, tpm_end) = match tpm_link {
            Some((swtpm_end, qemu_end)) => {
                let log = private_log(&vm_dir.join(tpm::LOG))?;
                let child = tpm::spawn(&vm_dir.join(tpm::DIR), swtpm_end, &cg, log, self.mode)?;
                (Some(child), Some(qemu_end))
            }
            None => (None, None),
        };
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
        for fd in qemu_end.into_iter().chain(tpm_end) {
            net::inherit_on_exec(&mut cmd, fd);
        }
        // Production only: the profile is installed by the package and
        // names the production paths.
        if self.mode == Mode::Production {
            confine::apparmor_on_exec(&mut cmd, confine::QEMU_PROFILE);
        }
        // A VM from an ISO has a blank disk: no base image, the ISO instead.
        let mut backing = match self.cdrom(cfg)? {
            Some(iso) => iso.into_iter().collect(),
            None => vec![images::image_path(&self.paths, &cfg.image)],
        };
        if let Some(source) = &cfg.throwaway_of {
            backing.push(self.paths.vm_dir(source).join(qemu::DISK));
        }
        let vnc_dir = cfg.vnc.then(|| self.paths.vnc_root().join(name));
        let rules = confine::qemu_rules(&vm_dir, &rt_dir, vnc_dir.as_deref(), &backing);
        confine::confine_on_exec(&mut cmd, confine::build(&rules)?);
        let mut child = cmd.spawn().with_context(|| match self.mode {
            Mode::Production => format!(
                "cannot start QEMU (is the AppArmor profile {} loaded?)",
                confine::QEMU_PROFILE
            ),
            Mode::Dev => "cannot start QEMU".to_owned(),
        })?;
        // Closes our copies of QEMU's socket ends, so passt and swtpm see
        // QEMU exit.
        drop(cmd);
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
        // Fail closed if QEMU is not confined as asked (profile in complain
        // mode, or replaced by an unconfined one).
        if self.mode == Mode::Production
            && let Err(e) = confine::check_profile(pid, confine::QEMU_PROFILE)
        {
            let _ = child.start_kill();
            let _ = child.wait().await;
            return Err(e);
        }
        // QEMU created the VNC socket before it answered QMP; it carries
        // QEMU's umask, so open it to API users here.
        if cfg.vnc {
            let sock = self.paths.vnc_socket(name);
            let mode = fs::Permissions::from_mode(self.shared_modes().1);
            // chmod follows symlinks: only ever touch QEMU's own socket.
            let shared = match fs::symlink_metadata(&sock) {
                Ok(m) if m.file_type().is_socket() => fs::set_permissions(&sock, mode),
                Ok(_) => Err(std::io::Error::other("not a socket")),
                Err(e) => Err(e),
            };
            if let Err(e) = shared {
                let _ = child.start_kill();
                let _ = child.wait().await;
                return Err(anyhow::Error::from(e).context("cannot share the VNC socket"));
            }
        }
        // passt checks its arguments at once; by the time QMP answers, a
        // passt that refused them has exited. The isolation is checked
        // again too: the table may have gone since `check_net`, and the
        // watchdog only sees the VM from here on.
        if let Some(p) = passt.as_mut() {
            let gone = match p.try_wait()? {
                Some(status) => Some(anyhow::anyhow!(
                    "passt exited ({status}); see {}",
                    vm_dir.join(PASST_LOG).display()
                )),
                None => net::check_isolation().err(),
            };
            if let Some(e) = gone {
                let _ = child.start_kill();
                let _ = child.wait().await;
                return Err(e);
            }
        }
        // swtpm answered QEMU's first commands before QMP came up; one that
        // died since, or a TPM QEMU did not wire up, fails the start.
        if let Some(t) = swtpm.as_mut() {
            let wrong = match t.try_wait()? {
                Some(status) => Some(anyhow::anyhow!(
                    "swtpm exited ({status}); see {}",
                    vm_dir.join(tpm::LOG).display()
                )),
                None => match qmp.execute("query-tpm", None).await {
                    Ok(reply) => check_tpm(&reply).err(),
                    Err(e) => Some(e.context("cannot query the TPM")),
                },
            };
            if let Some(e) = wrong {
                let _ = child.start_kill();
                let _ = child.wait().await;
                return Err(e);
            }
        }
        let (tx, rx) = watch::channel(false);
        // Set the moment QEMU is reaped, before the cleanup that `rx` waits
        // for.
        let (qemu_tx, qemu_rx) = watch::channel(false);
        let tpm = swtpm.map(|mut t| {
            let pid = t.id().expect("a child that was not waited for has a pid");
            let gone = Arc::new(AtomicBool::new(false));
            let (this, name, done, mut exited) =
                (self.clone(), name.clone(), gone.clone(), qemu_rx);
            // Reaps swtpm. It exits when QEMU closes its socket, or with
            // the cgroup. Otherwise the guest has lost its TPM: the VM is
            // killed rather than left running without it.
            tokio::spawn(async move {
                let r = t.wait().await;
                done.store(true, Ordering::Relaxed);
                // `is_ok` drops the borrow of the channel at once.
                let qemu_gone = tokio::time::timeout(SWTPM_GRACE, exited.wait_for(|e| *e))
                    .await
                    .is_ok();
                match r {
                    _ if !qemu_gone => {
                        tracing::error!("{name}: swtpm exited ({r:?}); stopping {name}");
                        if let Err(e) = this.cgroups.kill_vm(&name) {
                            tracing::error!("{name}: {e:#}");
                        }
                    }
                    Ok(s) if s.success() => tracing::debug!("{name}: swtpm exited"),
                    r => tracing::warn!("{name}: swtpm exited: {r:?}"),
                }
            });
            (pid, gone)
        });
        let net_down = Arc::new(AtomicBool::new(false));
        let cut_net = passt.map(|mut p| {
            let cut = Arc::new(tokio::sync::Notify::new());
            let wake = cut.clone();
            let down = net_down.clone();
            let name = name.clone();
            // Reaps passt. It exits when QEMU does, with the cgroup, or
            // when the isolation watchdog cuts the guest's network.
            tokio::spawn(async move {
                let r = tokio::select! {
                    r = p.wait() => r,
                    () = wake.notified() => {
                        let _ = p.start_kill();
                        p.wait().await
                    }
                };
                down.store(true, Ordering::Relaxed);
                match r {
                    Ok(s) if s.success() => tracing::debug!("{name}: passt exited"),
                    r => tracing::warn!("{name}: passt exited: {r:?}"),
                }
            });
            cut
        });

        let running = Arc::new(Running {
            config: cfg.clone(),
            pid,
            tpm,
            qmp,
            qga_sock: rt_dir.join(qemu::QGA_SOCK),
            rt_dir: rt_dir.clone(),
            screen_lock: tokio::sync::Mutex::new(()),
            input_lock: tokio::sync::Mutex::new(()),
            screen_size: Mutex::new(qemu::SCREEN),
            qga: tokio::sync::Mutex::new(None),
            disk_full: AtomicBool::new(false),
            net_down,
            cut_net,
            exited: rx,
        });
        self.running
            .lock()
            .unwrap()
            .insert(name.to_owned(), running.clone());
        tokio::spawn(self.clone().watch(name.clone(), child, tx, qemu_tx));
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
                (r.config.vcpus, m + self.overhead_mib(&r.config))
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
            overhead_mib: self.overhead_mib(cfg),
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
        let _op = self.lock(name).await?;
        let mut cfg = self.load(name)?;
        cfg.agent_control = on;
        cfg.save(&self.paths.vm_dir(name))
    }

    /// Turns the VNC socket on or off; it takes effect at the next start.
    pub async fn set_vnc(&self, name: &str, on: bool) -> Result<()> {
        self.check_exists(name)?;
        let _op = self.lock(name).await?;
        let mut cfg = self.load(name)?;
        ensure!(
            cfg.throwaway_of.is_none(),
            "{name} is a `stallo run` clone; it has no VNC"
        );
        cfg.vnc = on;
        cfg.save(&self.paths.vm_dir(name))
    }

    /// Puts pulled or imported installer ISO `iso` into the CD-ROM drive of
    /// a VM made from an ISO, or empties the drive (`None`); it takes effect
    /// at the next start. A RAM snapshot restored later runs with the drive
    /// as it is then, as if the disc had been swapped while the guest ran.
    pub async fn set_cdrom(&self, name: &str, iso: Option<&str>) -> Result<()> {
        self.check_exists(name)?;
        let _op = self.lock(name).await?;
        let mut cfg = self.load(name)?;
        ensure!(
            cfg.throwaway_of.is_none(),
            "{name} is a `stallo run` clone; change the VM it was made from"
        );
        ensure!(
            images::is_iso(&cfg.image).unwrap_or(false),
            "{name} has no CD-ROM drive; only VMs made from an installer ISO have one"
        );
        // Held until vm.toml names the ISO, so `images rm` sees it. Not
        // waited for: a pull holds it for its whole download, and the VM's
        // lock (stop, start) must not wait that long.
        let _image = self.images.try_read().map_err(|_| {
            anyhow::anyhow!("an image pull or removal is in progress; try again when it ends")
        })?;
        if let Some(id) = iso {
            ensure!(
                images::is_iso(id)?,
                "{id} is not an installer ISO; see `stallo images`"
            );
            images::ensure_pulled(&self.paths, id)?;
        }
        cfg.cdrom = iso.map(str::to_owned);
        cfg.save(&self.paths.vm_dir(name))
    }

    /// Changes a stopped VM's vCPUs and memory (`None`: unchanged), with
    /// the limits and host checks of `new`. Refused while the VM has RAM
    /// snapshots: they only load into a VM of the size they were taken at.
    pub async fn set_resources(
        &self,
        name: &str,
        vcpus: Option<u32>,
        memory_mib: Option<u64>,
    ) -> Result<VmConfig> {
        ensure!(
            vcpus.is_some() || memory_mib.is_some(),
            "nothing to change: give vcpus, memory or both"
        );
        self.check_exists(name)?;
        let _op = self.lock(name).await?;
        ensure!(
            self.running(name).is_none(),
            "{name} is running; stop it first to change its CPUs or memory: stallo stop {name}"
        );
        let mut cfg = self.load(name)?;
        ensure!(
            cfg.throwaway_of.is_none(),
            "{name} is a `stallo run` clone; change the VM it was made from"
        );
        let old = (cfg.vcpus, cfg.memory_mib);
        cfg.vcpus = vcpus.unwrap_or(cfg.vcpus);
        cfg.memory_mib = memory_mib.unwrap_or(cfg.memory_mib);
        cfg.validate()?;
        cfg.check_min_size()?;
        let ram: Vec<String> = self
            .list_snapshots(name)
            .await?
            .into_iter()
            .filter(|s| s.ram_bytes > 0)
            .map(|s| s.name)
            .collect();
        ensure!(
            ram.is_empty(),
            "{name} has RAM snapshots ({}) that only restore at its current size; delete them first: stallo snap {name} --delete <name>",
            ram.join(", ")
        );
        // As `new` (no new disk): would it start next to the running VMs?
        // Only for growth: shrinking never makes it fit worse, and every
        // start checks again.
        if cfg.vcpus > old.0 || cfg.memory_mib > old.1 {
            self.admit(&cfg, 0)?;
        }
        cfg.save(&self.paths.vm_dir(name))?;
        Ok(cfg)
    }

    /// Continues a paused VM, unless the disk is still below the floor.
    pub async fn resume(&self, name: &str) -> Result<()> {
        self.check_exists(name)?;
        let _op = self.lock(name).await?;
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

    /// QEMU's overhead, plus passt's for `internet` VMs and swtpm's for
    /// Windows VMs (one cgroup).
    fn overhead_mib(&self, cfg: &VmConfig) -> u64 {
        let passt = match cfg.net {
            NetProfile::Internet => net::PASST_MEMORY_MIB,
            NetProfile::Offline => 0,
        };
        let swtpm = if cfg.machine.is_linux() {
            0
        } else {
            tpm::MEMORY_MIB
        };
        overhead_mib(self.config.host.qemu_overhead_mib, cfg.memory_mib) + passt + swtpm
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
        qemu_tx: watch::Sender<bool>,
    ) {
        let status = child.wait().await;
        let _ = qemu_tx.send(true);
        tracing::info!("{name}: QEMU exited ({status:?})");
        if let Err(e) = self.cgroups.remove_vm(&name).await {
            tracing::error!("{name}: cgroup cleanup failed: {e:#}");
        }
        if let Err(e) = safe_remove(&self.paths.runtime, &self.paths.vm_runtime_dir(&name)) {
            tracing::error!("{name}: runtime dir cleanup failed: {e:#}");
        }
        if let Err(e) = safe_remove(&self.paths.runtime, &self.paths.vnc_root().join(&name)) {
            tracing::error!("{name}: VNC dir cleanup failed: {e:#}");
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
        let _op = self.lock(name).await?;
        self.stop_locked(name, force).await
    }

    /// [`Manager::stop`] for a caller that holds the VM's lifecycle lock.
    pub(crate) async fn stop_locked(&self, name: &str, force: bool) -> Result<()> {
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

    /// Production: kills every VM whose QEMU or swtpm is no longer confined
    /// by its AppArmor profile (e.g. the profile was reloaded in complain
    /// mode).
    pub fn check_confinement(&self) {
        if self.mode != Mode::Production {
            return;
        }
        for vm in self.all_running() {
            // An swtpm that has exited (its reaper stops the VM) has no
            // label to check.
            let swtpm = match &vm.tpm {
                Some((pid, gone))
                    if !gone.load(Ordering::Relaxed)
                        && Path::new(&format!("/proc/{pid}")).exists() =>
                {
                    confine::check_profile(*pid, confine::SWTPM_PROFILE)
                }
                _ => Ok(()),
            };
            if let Err(e) = confine::check_profile(vm.pid, confine::QEMU_PROFILE).and(swtpm) {
                tracing::error!("{}: {e:#}; killing it", vm.config.name);
                if let Err(e) = self.cgroups.kill_vm(&vm.config.name) {
                    tracing::error!("{}: {e:#}", vm.config.name);
                }
            }
        }
    }

    /// Kills every VM that still runs (its whole cgroup), without waiting.
    pub fn kill_all(&self) {
        for vm in self.all_running() {
            if let Err(e) = self.cgroups.kill_vm(&vm.config.name) {
                tracing::error!("{}: {e:#}", vm.config.name);
            }
        }
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
        let _op = self.lock(name).await?;
        ensure!(
            self.running(name).is_none(),
            "{name} is running; stop it first: stallo stop {name}"
        );
        safe_remove(&self.paths.data, &self.paths.vm_dir(name))?;
        Ok(())
    }

    pub(crate) fn running_vm(&self, name: &str) -> Result<Arc<Running>> {
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

    /// Whether the guest still has its network (an `internet` VM whose
    /// passt was not cut).
    pub fn has_network(&self) -> bool {
        self.cut_net.is_some() && !self.net_down.load(Ordering::Relaxed)
    }

    /// Kills passt: the guest loses its network at once and until it
    /// restarts. Needs no QMP, so a hung or hostile QEMU cannot delay it.
    /// Returns false if it was already cut or the VM has no network.
    pub fn cut_network(&self) -> bool {
        let Some(cut) = &self.cut_net else {
            return false;
        };
        if self.net_down.swap(true, Ordering::Relaxed) {
            return false;
        }
        // Stores a permit if the reaper is not waiting yet.
        cut.notify_one();
        true
    }

    /// What `ls` shows: QEMU's run state, e.g. `running`, `paused` or
    /// `io-error`, or `paused (disk full)` after the watchdog paused it.
    pub async fn state(&self) -> String {
        match self.status().await {
            Ok(s) if s == "paused" && self.disk_full.load(Ordering::Relaxed) => {
                "paused (disk full)".to_owned()
            }
            Ok(s) if self.net_down.load(Ordering::Relaxed) => format!("{s} (no network)"),
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
    let reason = crate::printable(last.unwrap_or("failed").trim_start_matches("dd: "), 200);
    bail!("cannot {what} {}: {reason}", path.escape_debug())
}

/// A fresh log file only the daemon user can read (mode 0600 even if it
/// existed with other permissions).
fn private_log(path: &Path) -> Result<fs::File> {
    let log = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("cannot open {}", path.display()))?;
    log.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(log)
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

/// QEMU's `query-tpm` reply for a Windows VM: exactly one TPM, the CRB
/// device on swtpm (`qemu::argv`). QEMU's reply is not echoed.
fn check_tpm(reply: &Value) -> Result<()> {
    let ok = reply.as_array().is_some_and(|tpms| {
        tpms.len() == 1 && tpms[0]["model"] == "tpm-crb" && tpms[0]["options"]["type"] == "emulator"
    });
    ensure!(ok, "QEMU did not attach the swtpm TPM (query-tpm)");
    Ok(())
}

/// The firmware variable template for `cfg`'s disk: Windows always gets
/// Secure Boot with Microsoft's keys, whatever its image says.
fn vars_firmware(cfg: &VmConfig, image: images::Firmware) -> images::Firmware {
    match cfg.machine {
        images::Os::Windows => images::Firmware::SecureBoot,
        images::Os::Linux => image,
    }
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
                throwaway_of: None,
                forwards: vec![],
                vnc: false,
                cdrom: None,
                machine: images::Os::Linux,
            },
            pid: 0,
            tpm: None,
            qmp,
            qga_sock: dir.path().join("qga.sock"),
            rt_dir: "/nonexistent".into(),
            screen_lock: tokio::sync::Mutex::new(()),
            input_lock: tokio::sync::Mutex::new(()),
            screen_size: Mutex::new(qemu::SCREEN),
            qga: tokio::sync::Mutex::new(None),
            disk_full: AtomicBool::new(false),
            net_down: Arc::default(),
            cut_net: None,
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

    /// The isolation watchdog cuts the network once; offline VMs have
    /// none to cut.
    #[tokio::test]
    async fn cutting_the_network() {
        let (_d, mut vm, log) = fake_vm("running", None).await;
        assert!(!vm.has_network() && !vm.cut_network());
        let cut = Arc::new(tokio::sync::Notify::new());
        vm.cut_net = Some(cut.clone());
        assert!(vm.has_network());
        assert!(vm.cut_network());
        assert!(!vm.cut_network(), "only once");
        assert!(!vm.has_network());
        // passt's reaper is woken even though it was not waiting yet.
        tokio::time::timeout(Duration::from_secs(1), cut.notified())
            .await
            .unwrap();
        assert_eq!(vm.state().await, "running (no network)");
        // No QMP command was needed.
        assert!(!log.lock().unwrap().iter().any(|c| c["execute"] == "stop"));
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
    fn tpm_reply() {
        let crb = serde_json::json!({
            "id": "tpm0",
            "model": "tpm-crb",
            "options": {"type": "emulator", "data": {"chardev": "tpm0-ctrl"}}
        });
        check_tpm(&Value::Array(vec![crb.clone()])).unwrap();
        let mut tis = crb.clone();
        tis["model"] = "tpm-tis".into();
        let mut passthrough = crb.clone();
        passthrough["options"]["type"] = "passthrough".into();
        for bad in [
            serde_json::json!([]),
            serde_json::json!([crb, crb]),
            serde_json::json!([tis]),
            serde_json::json!([passthrough]),
            serde_json::json!({}),
        ] {
            assert!(check_tpm(&bad).is_err(), "{bad}");
        }
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

    /// `images rm` keeps an ISO that a running VM started with, even after
    /// an eject in its vm.toml (it applies at the next start).
    #[tokio::test]
    async fn image_rm_sees_the_live_drive() {
        use crate::config::{DaemonConfig, Mode};
        let tmp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(tmp.path()).unwrap();
        for d in ["data", "run", "cg"] {
            fs::create_dir(root.join(d)).unwrap();
        }
        let paths = Paths::new(root.join("data"), root.join("run"))
            .unwrap()
            .prepare()
            .unwrap();
        let m = Manager::new(
            paths,
            DaemonConfig::default(),
            Cgroups::at(root.join("cg")),
            Mode::Dev,
        );
        m.cleanup_leftovers().await.unwrap();
        let id = "fedora-44-workstation";
        ensure_private_dir(&m.paths.images_dir()).unwrap();
        fs::write(images::iso_path(&m.paths, id), b"iso").unwrap();
        let (_d, mut running, _) = fake_vm("running", None).await;
        // Made from another ISO, so only the drive names this one.
        running.config.image = "ubuntu-26.04-desktop".into();
        running.config.cdrom = Some(id.into());
        let ejected = VmConfig {
            cdrom: None,
            ..running.config.clone()
        };
        let dir = m.paths.vm_dir("dev");
        fs::create_dir(&dir).unwrap();
        ejected.save(&dir).unwrap();
        m.running
            .lock()
            .unwrap()
            .insert("dev".into(), Arc::new(running));
        let e = m.remove_image(id).await.unwrap_err().to_string();
        assert!(e.contains("in use by dev;"), "{e}");
        // Stopped, the eject has applied.
        m.running.lock().unwrap().clear();
        m.remove_image(id).await.unwrap();
        assert!(!images::iso_path(&m.paths, id).exists());
    }

    /// A Windows VM gets Secure Boot variables and a CD-ROM drive (never a
    /// seed), whatever its image lookup says.
    #[tokio::test]
    async fn windows_firmware_and_drive() {
        use crate::config::{DaemonConfig, Mode};
        use images::{Firmware, Os};
        let tmp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(tmp.path()).unwrap();
        for d in ["data", "run", "cg"] {
            fs::create_dir(root.join(d)).unwrap();
        }
        let paths = Paths::new(root.join("data"), root.join("run"))
            .unwrap()
            .prepare()
            .unwrap();
        let m = Manager::new(
            paths,
            DaemonConfig::default(),
            Cgroups::at(root.join("cg")),
            Mode::Dev,
        );
        let (_d, running, _) = fake_vm("running", None).await;
        let linux = VmConfig {
            image: "left-the-catalog".into(),
            ..running.config.clone()
        };
        let win = VmConfig {
            machine: Os::Windows,
            ..linux.clone()
        };
        for fw in [Firmware::Uefi, Firmware::SecureBoot] {
            assert_eq!(vars_firmware(&win, fw), Firmware::SecureBoot);
            assert_eq!(vars_firmware(&linux, fw), fw);
        }
        // An image the catalog does not know: a seed for Linux, an empty
        // drive for Windows.
        assert_eq!(m.cdrom(&linux).unwrap(), None);
        assert_eq!(m.cdrom(&win).unwrap(), Some(None));
        // An imported ISO has a drive, whatever its OS.
        let local = VmConfig {
            image: "local-arch".into(),
            ..linux.clone()
        };
        assert_eq!(m.cdrom(&local).unwrap(), Some(None));
        let id = "fedora-44-workstation";
        let with_iso = VmConfig {
            cdrom: Some(id.into()),
            ..win
        };
        assert_eq!(
            m.cdrom(&with_iso).unwrap(),
            Some(Some(images::iso_path(&m.paths, id)))
        );
    }

    /// `set_resources`: limits and host checks of `new`, stopped VMs only,
    /// no run clones, no RAM snapshots; saved in vm.toml.
    #[tokio::test]
    async fn resources_setting() {
        use crate::config::{DaemonConfig, MAX_MEMORY_MIB, Mode};
        let tmp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(tmp.path()).unwrap();
        for d in ["data", "run", "cg"] {
            fs::create_dir(root.join(d)).unwrap();
        }
        let paths = Paths::new(root.join("data"), root.join("run"))
            .unwrap()
            .prepare()
            .unwrap();
        let mut config = DaemonConfig::default();
        // Admission must pass on any test host's disk.
        config.host.disk_floor_gib = 0;
        let m = Manager::new(paths, config, Cgroups::at(root.join("cg")), Mode::Dev);
        m.cleanup_leftovers().await.unwrap();
        let (_d, running, _) = fake_vm("running", None).await;
        let base = running.config.clone();
        let clone = VmConfig {
            name: "run-0a1b2c3d".into(),
            throwaway_of: Some("dev".into()),
            ..base.clone()
        };
        for cfg in [&base, &clone] {
            let dir = m.paths.vm_dir(&cfg.name);
            fs::create_dir(&dir).unwrap();
            cfg.save(&dir).unwrap();
        }
        let err = |r: Result<VmConfig>| r.unwrap_err().to_string();

        assert!(err(m.set_resources("dev", None, None).await).contains("nothing to change"));
        assert!(err(m.set_resources("nope", Some(1), None).await).contains("nope"));
        assert!(err(m.set_resources("dev", Some(0), None).await).contains("vcpus must be"));
        assert!(err(m.set_resources("dev", None, Some(255)).await).contains("memory must be"));
        let e = err(m.set_resources("run-0a1b2c3d", Some(2), None).await);
        assert!(e.contains("clone"), "{e}");
        m.running
            .lock()
            .unwrap()
            .insert("dev".into(), Arc::new(running));
        let e = err(m.set_resources("dev", Some(2), None).await);
        assert!(e.contains("dev is running; stop it first"), "{e}");
        m.running.lock().unwrap().clear();
        assert_eq!(m.load("dev").unwrap(), base, "nothing saved");

        // Below: snapshots are listed with a confined qemu-img.
        if !confine::available() {
            return;
        }
        let dir = m.paths.vm_dir("dev");
        for (file, size) in [(qemu::DISK, "1G"), (qemu::VARS, "1M")] {
            let ok = std::process::Command::new("qemu-img")
                .args(["create", "-q", "-f", "qcow2"])
                .arg(dir.join(file))
                .arg(size)
                .status()
                .unwrap()
                .success();
            assert!(ok);
        }
        let cfg = m.set_resources("dev", Some(2), Some(1024)).await.unwrap();
        assert_eq!((cfg.vcpus, cfg.memory_mib), (2, 1024));
        assert_eq!(m.load("dev").unwrap(), cfg, "vm.toml round-trip");
        let cfg = m.set_resources("dev", None, Some(768)).await.unwrap();
        assert_eq!((cfg.vcpus, cfg.memory_mib), (2, 768), "vcpus kept");
        assert_eq!(
            VmConfig {
                vcpus: base.vcpus,
                memory_mib: base.memory_mib,
                ..cfg.clone()
            },
            base,
            "nothing else changed"
        );

        // Growth must fit the host; shrinking is always allowed (start
        // checks again), even for a VM that does not fit now.
        let over = m.set_resources("dev", None, Some(MAX_MEMORY_MIB)).await;
        assert!(err(over).contains("over the VM memory budget"));
        assert_eq!(m.load("dev").unwrap(), cfg, "nothing saved");
        let huge = VmConfig {
            vcpus: 255,
            memory_mib: MAX_MEMORY_MIB,
            ..cfg.clone()
        };
        huge.save(&dir).unwrap();
        let shrunk = m
            .set_resources("dev", Some(254), Some(MAX_MEMORY_MIB - 1024))
            .await
            .unwrap();
        assert_eq!(
            (shrunk.vcpus, shrunk.memory_mib),
            (254, MAX_MEMORY_MIB - 1024)
        );
        let e = err(m.set_resources("dev", Some(255), None).await);
        assert!(e.contains("too many"), "{e}");
        cfg.save(&dir).unwrap();

        // A RAM snapshot only loads at the size it was taken at; checked
        // before the host (a growth names the snapshots, not the budget).
        crate::snapshot::create_offline(&dir, "s1").await.unwrap();
        ensure_private_dir(&dir.join(qemu::STATES)).unwrap();
        fs::write(crate::snapshot::state_file(&dir, "s1"), b"ram").unwrap();
        let e = err(m.set_resources("dev", Some(1), None).await);
        assert!(e.contains("RAM snapshots (s1)"), "{e}");
        assert_eq!(m.load("dev").unwrap(), cfg, "nothing saved");
        let e = err(m.set_resources("dev", None, Some(MAX_MEMORY_MIB)).await);
        assert!(e.contains("RAM snapshots (s1)"), "{e}");
    }

    /// An import is refused at once while a pull, removal, VM creation or
    /// another import holds the images lock, and when its ISO would not fit
    /// above the disk floor; neither leaves anything behind.
    #[tokio::test]
    async fn import_admission() {
        use crate::config::{DaemonConfig, Mode};
        use images::Os;
        let tmp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(tmp.path()).unwrap();
        let manager = |floor_gib, dir: &str| {
            for d in ["data", "run", "cg"] {
                fs::create_dir_all(root.join(dir).join(d)).unwrap();
            }
            let paths = Paths::new(root.join(dir).join("data"), root.join(dir).join("run"))
                .unwrap()
                .prepare()
                .unwrap();
            let mut config = DaemonConfig::default();
            config.host.disk_floor_gib = floor_gib;
            Manager::new(
                paths,
                config,
                Cgroups::at(root.join(dir).join("cg")),
                Mode::Dev,
            )
        };
        let data = vec![0u8; 0x9000];
        let size = data.len() as u64;
        let left = |m: &Manager| fs::read_dir(m.paths.images_dir()).unwrap().count();

        let full = manager(u64::MAX >> 30, "full");
        let e = full
            .import_iso("local-x", Os::Linux, "", size, &mut &data[..])
            .await
            .unwrap_err();
        assert!(format!("{e:#}").contains("not enough disk space"), "{e:#}");
        assert_eq!(left(&full), 0);

        let m = manager(0, "ok");
        for exclusive in [true, false] {
            let _held = if exclusive {
                (Some(m.images.write().await), None)
            } else {
                (None, Some(m.images.read().await))
            };
            let e = m
                .import_iso("local-x", Os::Linux, "", size, &mut &data[..])
                .await
                .unwrap_err();
            assert!(format!("{e:#}").contains("in progress"), "{e:#}");
        }
        // A second import while the first waits for its client.
        let (_client, mut body) = tokio::io::duplex(64);
        let mut second = &data[..];
        tokio::select! {
            biased;
            r = m.import_iso("local-a", Os::Linux, "", size, &mut body) => {
                panic!("the first import ended: {r:?}")
            }
            r = m.import_iso("local-b", Os::Linux, "", size, &mut second) => {
                let e = r.unwrap_err();
                assert!(format!("{e:#}").contains("in progress"), "{e:#}");
            }
        }
        assert!(!images::iso_path(&m.paths, "local-b").exists());
    }
}
