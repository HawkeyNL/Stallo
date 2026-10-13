//! Snapshots: internal qcow2 snapshots of a VM's disk and firmware
//! variables, plus the RAM of a running VM in a file of its own.
//!
//! A stopped VM gets disk-only snapshots through `qemu-img` (confined like
//! QEMU). A running VM is snapshotted with QMP jobs (`snapshot-save`,
//! `-load`, `-delete`) on `disk0` and `fw-vars`, so firmware variables
//! always match the disk; the guest is paused while its RAM ("vmstate") is
//! written.
//!
//! **Each RAM snapshot gets its own image**, `states/<name>.qcow2`, added to
//! QEMU (`blockdev-add`) only for the job. Measured reason: QEMU's qcow2
//! drops the RAM clusters from an image's active state after a save, but
//! not after a load. RAM stored in an image that a restore went through is
//! therefore copied cluster by cluster before the next save overwrites it:
//! with the RAM in the disk image, a snapshot taken after a restore paused
//! a 2 GiB guest for 30 s instead of 2.3 s. A fresh image per snapshot is
//! never shared, and deleting a snapshot frees its RAM at once.
//!
//! QEMU is untrusted: snapshot lists are parsed into typed values, names
//! that Stallo would never create are dropped, and job errors are cut and
//! stripped of control characters before they reach a client.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::process::Command;
use tokio::sync::broadcast::error::RecvError;

use crate::config::validate_tag;
use crate::paths::safe_remove;
use crate::qmp::Qmp;
use crate::vm::{Manager, QGA_BUSY_WAIT, Running};
use crate::{cgroup, confine, host, qemu, run_tool};

/// The block nodes every snapshot covers (named in `qemu::argv`).
const DEVICES: [&str; 2] = ["disk0", "fw-vars"];
/// The node name of a RAM snapshot's image while a job uses it.
const VMSTATE: &str = "state";
/// Longest a snapshot job may take, every QMP reply included. RAM is
/// written at hundreds of MB/s, so this only trips on a stuck job.
const JOB_TIMEOUT: Duration = Duration::from_secs(600);
/// Job status is polled this often while no event arrives (events are
/// missed when the broadcast lags).
const JOB_POLL: Duration = Duration::from_secs(1);
/// How long a restore waits for the guest agent to answer again.
const AGENT_AFTER_RESTORE: Duration = Duration::from_secs(10);
/// Most snapshots per VM. Each can hold the full guest RAM, agents may take
/// snapshots but never delete them, and the QMP reply that lists them must
/// stay far below the reply cap.
pub const MAX_SNAPSHOTS: usize = 16;

/// One snapshot, as `snaps` lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub name: String,
    /// Host disk space its saved RAM takes; 0 for a disk-only snapshot.
    pub ram_bytes: u64,
    /// When it was taken: seconds since the Unix epoch (host clock).
    pub created: u64,
    /// Guest uptime when it was taken, in milliseconds.
    pub vm_clock_ms: u64,
}

/// QEMU's `SnapshotInfo` (QMP and `qemu-img info` use the same shape).
#[derive(Deserialize)]
struct RawSnapshot {
    name: String,
    #[serde(rename = "date-sec")]
    date_sec: u64,
    #[serde(rename = "date-nsec")]
    date_nsec: u64,
    #[serde(rename = "vm-clock-sec")]
    vm_clock_sec: u64,
    #[serde(rename = "vm-clock-nsec")]
    vm_clock_nsec: u64,
}

/// Parses a `snapshots` array (missing means none), oldest first. Names
/// Stallo would never create are dropped. `ram_bytes` is filled in later
/// ([`with_ram`]).
pub fn parse_list(v: Value) -> Result<Vec<Snapshot>> {
    if v.is_null() {
        return Ok(Vec::new());
    }
    let mut raw: Vec<RawSnapshot> = serde_json::from_value(v).context("invalid snapshot list")?;
    raw.retain(|s| validate_tag(&s.name).is_ok());
    raw.sort_by_key(|s| (s.date_sec, s.date_nsec));
    Ok(raw
        .into_iter()
        .map(|s| Snapshot {
            name: s.name,
            ram_bytes: 0,
            created: s.date_sec,
            vm_clock_ms: s
                .vm_clock_sec
                .saturating_mul(1000)
                .saturating_add(s.vm_clock_nsec / 1_000_000),
        })
        .collect())
}

/// The image that holds the RAM of snapshot `tag` (tags are valid file
/// names: letters, digits, `.`, `_`, `-`, starting with a letter).
pub fn state_file(vm_dir: &Path, tag: &str) -> PathBuf {
    vm_dir.join(qemu::STATES).join(format!("{tag}.qcow2"))
}

/// Sets `ram_bytes` from the snapshots' RAM images (space used on disk).
fn with_ram(mut list: Vec<Snapshot>, vm_dir: &Path) -> Vec<Snapshot> {
    use std::os::unix::fs::MetadataExt;
    for s in &mut list {
        if let Ok(m) = std::fs::symlink_metadata(state_file(vm_dir, &s.name))
            && m.is_file()
        {
            s.ram_bytes = (m.blocks() * 512).max(1);
        }
    }
    list
}

/// The first free name of the form `snap<N>`.
pub fn next_name(names: &[String]) -> String {
    (1..)
        .map(|n| format!("snap{n}"))
        .find(|t| !names.contains(t))
        .expect("a free name exists")
}

/// A running VM's snapshots (from `disk0`, without RAM sizes), and every
/// snapshot name in use on either node: a save that failed halfway can
/// leave a name on one of them only, and QEMU refuses to reuse it.
pub async fn list_live(qmp: &Qmp) -> Result<(Vec<Snapshot>, Vec<String>)> {
    let mut nodes = qmp
        .execute("query-named-block-nodes", Some(json!({"flat": true})))
        .await?;
    let nodes = nodes.as_array_mut().context("invalid block node list")?;
    let (mut list, mut names) = (None, Vec::new());
    for node in nodes {
        let Some(n) = node["node-name"].as_str().filter(|n| DEVICES.contains(n)) else {
            continue;
        };
        let is_disk = n == DEVICES[0];
        let snaps = parse_list(node["image"]["snapshots"].take())?;
        names.extend(snaps.iter().map(|s| s.name.clone()));
        if is_disk {
            list = Some(snaps);
        }
    }
    names.sort();
    names.dedup();
    let list = list.context("QEMU did not report the disk")?;
    Ok((list, names))
}

/// Creates the empty image for the RAM of a new snapshot (replacing one
/// that a failure left behind). 2 MiB clusters: few metadata updates.
async fn create_state_file(vm_dir: &Path, file: &Path) -> Result<()> {
    safe_remove(vm_dir, file)?;
    run_tool(
        Command::new("qemu-img")
            .args(["create", "-q", "-f", "qcow2", "-o", "cluster_size=2M"])
            .arg(file)
            .arg("2M"),
        Duration::from_secs(30),
    )
    .await
    .inspect_err(|_| {
        let _ = std::fs::remove_file(file);
    })
    .context("cannot create the image for the snapshot's RAM")?;
    Ok(())
}

/// Runs a snapshot job with `file` attached as node [`VMSTATE`]. The page
/// cache is used for it (no `cache.direct`): QEMU's unaligned, queue-depth-1
/// stream makes O_DIRECT 3-5x slower (docs/ram-snapshot-io.md), and the
/// pages count against the VM's own cgroup. QEMU flushes the image before
/// the snapshot counts; never set `cache.no-flush`.
async fn with_state<T>(qmp: &Qmp, file: &Path, job: impl AsyncFnOnce() -> Result<T>) -> Result<T> {
    // A node left by an interrupted job would block the name.
    let _ = qmp
        .execute("blockdev-del", Some(json!({"node-name": VMSTATE})))
        .await;
    // Never a backing file, whatever QEMU wrote into the image's header.
    let node = json!({"driver": "qcow2", "node-name": VMSTATE, "discard": "unmap",
        "backing": null,
        "file": {"driver": "file", "filename": file, "discard": "unmap"}});
    qmp.execute("blockdev-add", Some(node))
        .await
        .context("cannot attach the snapshot's RAM image")?;
    let result = job().await;
    if let Err(e) = qmp
        .execute("blockdev-del", Some(json!({"node-name": VMSTATE})))
        .await
    {
        tracing::warn!("cannot detach the snapshot's RAM image: {e:#}");
    }
    drop_cache(file);
    result
}

/// Drops the RAM image's pages from the page cache (they are clean once
/// QEMU flushed and closed it), so they neither crowd the VM's cgroup nor
/// make the host look fuller than it is. Best effort.
fn drop_cache(file: &Path) {
    use rustix::fs::{Advice, Mode, OFlags};
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let dropped = rustix::fs::open(file, flags, Mode::empty())
        .and_then(|fd| rustix::fs::fadvise(&fd, 0, None, Advice::DontNeed));
    if let Err(e) = dropped {
        tracing::debug!("cannot drop the page cache of {}: {e}", file.display());
    }
}

/// Saves the running VM's disk and firmware variables as `tag`, and its RAM
/// into `file` (an empty image). Returns how long the guest was paused.
/// QEMU resumes the guest itself; if it does not, `cont` follows unless
/// `hold` is set.
pub async fn save(
    qmp: &Qmp,
    tag: &str,
    file: &Path,
    hold: &AtomicBool,
) -> Result<Option<Duration>> {
    let was_running = status(qmp).await? == "running";
    let args =
        json!({"tag": tag, "vmstate": VMSTATE, "devices": [DEVICES[0], DEVICES[1], VMSTATE]});
    let pause = with_state(qmp, file, async || {
        run_job(qmp, "snapshot-save", args, JOB_TIMEOUT).await
    })
    .await?;
    if was_running {
        cont_unless_held(qmp, hold).await?;
    }
    Ok(pause)
}

/// What a load did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Loaded {
    /// How long the guest was paused, if QEMU paused and resumed it.
    pub pause: Option<Duration>,
    /// Whether Stallo had to `cont` the guest after the load.
    pub continued: bool,
}

/// Loads `tag`: disk, firmware variables, and RAM from `file`. With `run`,
/// the guest runs afterwards: QEMU resumes a guest that ran before the
/// load, and `cont` covers the rest (a guest started paused), unless
/// `hold` is set.
pub async fn load(
    qmp: &Qmp,
    tag: &str,
    file: &Path,
    run: bool,
    hold: &AtomicBool,
) -> Result<Loaded> {
    let args =
        json!({"tag": tag, "vmstate": VMSTATE, "devices": [DEVICES[0], DEVICES[1], VMSTATE]});
    let pause = with_state(qmp, file, async || {
        run_job(qmp, "snapshot-load", args, JOB_TIMEOUT).await
    })
    .await?;
    let continued = run && cont_unless_held(qmp, hold).await?;
    Ok(Loaded { pause, continued })
}

/// Deletes `tag` from the disk and firmware variables of a running VM (its
/// RAM image is a file the caller removes).
pub async fn delete(qmp: &Qmp, tag: &str) -> Result<()> {
    let args = json!({"tag": tag, "devices": DEVICES});
    run_job(qmp, "snapshot-delete", args, JOB_TIMEOUT).await?;
    Ok(())
}

async fn status(qmp: &Qmp) -> Result<String> {
    let v = qmp.execute("query-status", None).await?;
    Ok(v["status"].as_str().unwrap_or("unknown").to_owned())
}

/// Resumes the guest unless it runs or `hold` (the disk watchdog paused it)
/// is set. Returns whether `cont` was sent.
///
/// Known gap: a watchdog `stop` sent during a long job times out and clears
/// `hold`, but QEMU still runs it after the job; the guest is then resumed
/// below the floor until the next watchdog tick (10 s) pauses it again.
async fn cont_unless_held(qmp: &Qmp, hold: &AtomicBool) -> Result<bool> {
    if hold.load(Ordering::Relaxed) || status(qmp).await? == "running" {
        return Ok(false);
    }
    qmp.execute("cont", None).await?;
    // The watchdog may have paused it between the check and `cont`.
    if hold.load(Ordering::Relaxed) {
        qmp.execute("stop", None).await?;
    }
    Ok(true)
}

/// Job ids are unique per daemon, so a job left behind by a failure never
/// blocks the next one.
static JOB_IDS: AtomicU64 = AtomicU64::new(1);

/// Starts a snapshot job, waits until it concludes (`JOB_STATUS_CHANGE`,
/// with polling as a fallback), dismisses it and returns its error, if
/// any. Also returns how long the guest was paused (`STOP` to `RESUME`).
///
/// One time budget, `limit`, covers the whole job: QEMU's main loop is busy
/// while the job runs, so every reply (even to `query-jobs`) may wait until
/// the job is done, and each call may use all the time that is left.
async fn run_job(
    qmp: &Qmp,
    command: &str,
    mut args: Value,
    limit: Duration,
) -> Result<Option<Duration>> {
    let id = format!("stallo-{}", JOB_IDS.fetch_add(1, Ordering::Relaxed));
    args["job-id"] = id.clone().into();
    let deadline = Instant::now() + limit;
    let left = || deadline.saturating_duration_since(Instant::now());
    // Subscribed before the job starts, so no event is missed.
    let mut events = qmp.events();
    qmp.execute_timeout(command, Some(args), left()).await?;
    // QEMU's own event times: its main loop is busy during the job, so
    // STOP and RESUME arrive here together.
    let (mut stopped, mut pause) = (None, None);
    let late = || anyhow::anyhow!("{command} did not finish within {limit:?}");
    loop {
        ensure!(!left().is_zero(), late());
        match tokio::time::timeout(JOB_POLL, events.recv()).await {
            Ok(Ok(e)) => {
                match e.event.as_str() {
                    "STOP" => stopped = Some(e.micros),
                    "RESUME" => {
                        pause = stopped.map(|s| Duration::from_micros(e.micros.saturating_sub(s)));
                    }
                    "JOB_STATUS_CHANGE"
                        if e.data["id"] == id.as_str() && e.data["status"] == "concluded" =>
                    {
                        break;
                    }
                    _ => {}
                }
                continue;
            }
            Ok(Err(RecvError::Closed)) => bail!("QEMU exited during {command}"),
            // Lagged or quiet: ask instead.
            Ok(Err(RecvError::Lagged(_))) | Err(_) => {}
        }
        let polled = job(qmp, &id, left()).await;
        if polled.is_err() && left().is_zero() {
            return Err(late());
        }
        if polled?["status"] == "concluded" {
            break;
        }
    }
    let error = job(qmp, &id, left()).await?["error"]
        .as_str()
        .map(|e| crate::printable(e, 200));
    qmp.execute("job-dismiss", Some(json!({"id": id}))).await?;
    match error {
        Some(e) => bail!("{command} failed: {e}"),
        None => Ok(pause),
    }
}

/// The `query-jobs` entry of job `id`.
async fn job(qmp: &Qmp, id: &str, wait: Duration) -> Result<Value> {
    let mut jobs = qmp.execute_timeout("query-jobs", None, wait).await?;
    jobs.as_array_mut()
        .and_then(|j| j.iter_mut().find(|j| j["id"] == id))
        .map(Value::take)
        .with_context(|| format!("snapshot job {id} disappeared"))
}

/// A snapshot that was just taken.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Taken {
    pub name: String,
    /// Whether it holds RAM (only running VMs have it).
    pub ram: bool,
    /// How long the guest was paused, in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pause_ms: Option<u64>,
    /// How long the whole snapshot took, in milliseconds.
    pub ms: u64,
}

/// A snapshot that was just restored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Restored {
    pub name: String,
    /// The VM's state afterwards (`running`, `stopped`, ...).
    pub state: String,
    /// How long the guest was paused, in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pause_ms: Option<u64>,
    /// How long the whole restore took, in milliseconds.
    pub ms: u64,
    /// After a RAM snapshot: how long after the load the guest agent
    /// answered again (reconnected and synced), in milliseconds, roughly.
    /// `None` if it did not within 10 s (for example, the snapshot was taken
    /// before the agent ran) or the VM is not running.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_ms: Option<u64>,
}

fn ms(d: Duration) -> u64 {
    d.as_millis() as u64
}

/// The images of a stopped VM that hold snapshots, in [`DEVICES`] order.
fn offline_files(vm_dir: &Path) -> [PathBuf; 2] {
    [qemu::DISK, qemu::VARS].map(|f| vm_dir.join(f))
}

const QEMU_IMG: &str = "/usr/bin/qemu-img";

/// `qemu-img` on a stopped VM's own images. A compromised QEMU may have
/// crafted them, so it runs confined like QEMU (Landlock and seccomp, only
/// these files writable) and never opens a backing file: the image is named
/// as `json:{..., "backing": null}`.
async fn qemu_img(args: &[&str], image: &Path, files: &[PathBuf]) -> Result<Vec<u8>> {
    let path = image.to_str().context("VM path is not UTF-8")?;
    let spec = json!({"driver": "qcow2", "backing": null,
        "file": {"driver": "file", "filename": path}});
    let mut cmd = Command::new(QEMU_IMG);
    cmd.args(args).arg(format!("json:{spec}"));
    // Order matters: the cgroup hook opens files the ruleset denies.
    cgroup::confine_tool(&mut cmd)?;
    confine::confine_on_exec(&mut cmd, confine::build(&confine::tool_rules(files))?);
    crate::run_prepared(&mut cmd, Duration::from_secs(60)).await
}

/// The snapshots in one image of a stopped VM.
async fn image_snapshots(image: &Path, files: &[PathBuf]) -> Result<Vec<Snapshot>> {
    let out = qemu_img(&["info", "--output=json"], image, files).await?;
    let mut info: Value = serde_json::from_slice(&out).context("invalid qemu-img output")?;
    parse_list(info["snapshots"].take())
}

/// A stopped VM's snapshots (from its disk, without RAM sizes).
pub async fn list_offline(vm_dir: &Path) -> Result<Vec<Snapshot>> {
    let files = offline_files(vm_dir);
    image_snapshots(&files[0], &files).await
}

/// The snapshot names in each image of a stopped VM ([`DEVICES`] order).
/// They differ only after a failure.
pub async fn names_offline(vm_dir: &Path) -> Result<[Vec<String>; 2]> {
    let files = offline_files(vm_dir);
    let mut names: [Vec<String>; 2] = Default::default();
    for (f, n) in files.iter().zip(&mut names) {
        *n = image_snapshots(f, &files)
            .await?
            .into_iter()
            .map(|s| s.name)
            .collect();
    }
    Ok(names)
}

/// Every name in use on any image.
fn all_names(per_image: &[Vec<String>]) -> Vec<String> {
    let mut names = per_image.concat();
    names.sort();
    names.dedup();
    names
}

/// Takes a disk-only snapshot of a stopped VM: `tag` on both images, or on
/// none (a failure removes it again).
pub async fn create_offline(vm_dir: &Path, tag: &str) -> Result<()> {
    let files = offline_files(vm_dir);
    for (i, f) in files.iter().enumerate() {
        if let Err(e) = qemu_img(&["snapshot", "-c", tag], f, &files).await {
            // Also the failed image: it may have the tag anyway (timeout).
            for done in &files[..=i] {
                let _ = qemu_img(&["snapshot", "-d", tag], done, &files).await;
            }
            return Err(e);
        }
    }
    Ok(())
}

/// Reverts a stopped VM's disk and firmware variables to `tag` (the RAM is
/// not used). Refused unless both images have it, so a restore never stops
/// halfway for that reason.
pub async fn apply_offline(vm_dir: &Path, tag: &str, names: &[Vec<String>; 2]) -> Result<()> {
    ensure!(
        names.iter().all(|n| n.iter().any(|t| t == tag)),
        "snapshot {tag} is incomplete (a step that created or deleted it failed); delete it"
    );
    let files = offline_files(vm_dir);
    for f in &files {
        qemu_img(&["snapshot", "-a", tag], f, &files)
            .await
            .context("the restore stopped halfway; restore again")?;
    }
    Ok(())
}

/// Deletes `tag` from every image of a stopped VM that has it.
pub async fn delete_offline(vm_dir: &Path, tag: &str, names: &[Vec<String>; 2]) -> Result<()> {
    let files = offline_files(vm_dir);
    for (f, n) in files.iter().zip(names) {
        if n.iter().any(|t| t == tag) {
            qemu_img(&["snapshot", "-d", tag], f, &files).await?;
        }
    }
    Ok(())
}

impl Manager {
    /// Takes a snapshot named `tag` (default `snap<N>`). A running VM's
    /// snapshot holds its RAM; a stopped VM's holds disk and firmware
    /// variables only. Refused unless the data disk keeps its floor free,
    /// with room for the guest RAM when it is saved.
    pub async fn snapshot(&self, name: &str, tag: Option<&str>) -> Result<Taken> {
        let started = Instant::now();
        self.check_exists(name)?;
        let _op = self.lock(name).await?;
        let vm_dir = self.paths.vm_dir(name);
        let vm = self.running(name);
        let names = match &vm {
            Some(vm) => list_live(&vm.qmp).await?.1,
            None => all_names(&names_offline(&vm_dir).await?),
        };
        let tag = pick_new_name(&names, tag)?;
        let ram = vm.as_ref().map_or(0, |vm| vm.config.memory_mib << 20);
        host::check_snapshot_space(
            host::disk_free(&self.paths.data)?,
            self.config.host.disk_floor_gib,
            ram,
        )?;
        let pause = match &vm {
            Some(vm) => {
                let file = state_file(&vm_dir, &tag);
                create_state_file(&vm_dir, &file).await?;
                let saved = save(&vm.qmp, &tag, &file, &vm.disk_full).await;
                if saved.is_err() {
                    // The tag may be on the disk already: without its RAM it
                    // would look like a disk-only snapshot.
                    if let Err(e) = delete(&vm.qmp, &tag).await {
                        tracing::warn!("{name}: cannot remove failed snapshot {tag}: {e:#}");
                    }
                    let _ = safe_remove(&vm_dir, &file);
                }
                saved?
            }
            None => {
                create_offline(&vm_dir, &tag).await?;
                None
            }
        };
        tracing::info!("{name}: snapshot {tag} taken, paused {pause:?}");
        Ok(Taken {
            name: tag,
            ram: vm.is_some(),
            pause_ms: pause.map(ms),
            ms: ms(started.elapsed()),
        })
    }

    /// The VM's snapshots, oldest first.
    pub async fn snapshots(&self, name: &str) -> Result<Vec<Snapshot>> {
        self.check_exists(name)?;
        let _op = self.lock(name).await?;
        self.list_snapshots(name).await
    }

    /// The VM's snapshots with their RAM sizes (lifecycle lock held).
    async fn list_snapshots(&self, name: &str) -> Result<Vec<Snapshot>> {
        let vm_dir = self.paths.vm_dir(name);
        let list = match self.running(name) {
            Some(vm) => list_live(&vm.qmp).await?.0,
            None => list_offline(&vm_dir).await?,
        };
        Ok(with_ram(list, &vm_dir))
    }

    /// Restores snapshot `tag` (default: the newest).
    ///
    /// - Running VM, RAM snapshot: the guest gets the snapshot's RAM back
    ///   and runs on from there. The guest-agent connection is dropped,
    ///   since the agent's state went back too.
    /// - Stopped VM, RAM snapshot: the VM starts from it (QEMU starts with
    ///   its CPUs stopped, loads the snapshot, then runs).
    /// - Stopped VM, disk-only snapshot: disk and firmware variables go
    ///   back; the VM stays stopped.
    /// - Running VM, disk-only snapshot: refused; stop the VM first.
    pub async fn restore(self: &Arc<Self>, name: &str, tag: Option<&str>) -> Result<Restored> {
        let started = Instant::now();
        self.check_exists(name)?;
        let _op = self.lock(name).await?;
        let vm_dir = self.paths.vm_dir(name);
        let snap = pick_existing(&self.list_snapshots(name).await?, name, tag)?;
        ensure!(
            !ram_missing(&snap),
            "the RAM image of {} is missing; it cannot be restored, delete it",
            snap.name
        );
        let file = state_file(&vm_dir, &snap.name);
        let pause = match self.running(name) {
            Some(vm) => {
                ensure!(
                    snap.ram_bytes > 0,
                    "{} has no RAM state; stop the VM first, then restore it: stallo stop {name}",
                    snap.name
                );
                let run = vm.status().await? == "running";
                self.load_into(&vm, &snap.name, &file, run).await?
            }
            None if snap.ram_bytes > 0 => {
                // Not `-loadvm`: it cannot be told where the RAM is.
                let vm = self.start_locked(name, true).await?;
                match self.load_into(&vm, &snap.name, &file, true).await {
                    Ok(pause) => pause,
                    Err(e) => {
                        if let Err(stop) = self.stop_locked(name, true).await {
                            tracing::error!("{name}: stop after failed restore: {stop:#}");
                        }
                        // The load reverts the images before the RAM.
                        return Err(e.context(format!(
                            "{name} was stopped again; its disk may already be at {}",
                            snap.name
                        )));
                    }
                }
            }
            None => {
                apply_offline(&vm_dir, &snap.name, &names_offline(&vm_dir).await?).await?;
                None
            }
        };
        let state = match self.running(name) {
            Some(vm) => vm.state().await,
            None => "stopped".to_owned(),
        };
        // The old agent connection was dropped with the load: reconnect and
        // sync now, so the caller knows the guest is usable. Never fails
        // the restore, which has happened.
        let agent = if state == "running" {
            self.wait_ready(name, AGENT_AFTER_RESTORE)
                .await
                .inspect_err(|e| tracing::warn!("{name}: {e:#}"))
                .ok()
        } else {
            None
        };
        tracing::info!("{name}: restored {}, now {state}", snap.name);
        Ok(Restored {
            name: snap.name,
            state,
            pause_ms: pause.map(ms),
            ms: ms(started.elapsed()),
            agent_ms: agent.map(ms),
        })
    }

    /// Loads RAM snapshot `tag` (RAM in `file`) into the running QEMU of
    /// `vm` and drops the kept guest-agent connection. Returns how long the
    /// guest was paused.
    async fn load_into(
        &self,
        vm: &Running,
        tag: &str,
        file: &Path,
        run: bool,
    ) -> Result<Option<Duration>> {
        // No guest-agent operation may straddle the load.
        let mut agent = tokio::time::timeout(QGA_BUSY_WAIT, vm.qga.lock())
            .await
            .map_err(|_| {
                anyhow::anyhow!("{} is busy with a guest command; try again", vm.config.name)
            })?;
        let loaded = load(&vm.qmp, tag, file, run, &vm.disk_full).await;
        *agent = None;
        let loaded =
            loaded.with_context(|| format!("cannot restore {tag}; the VM may be left paused"))?;
        tracing::debug!("{}: loaded {tag}: {loaded:?}", vm.config.name);
        Ok(loaded.pause)
    }

    /// Deletes snapshot `tag` and its RAM image, also a snapshot that a
    /// failed save left on some images only.
    pub async fn delete_snapshot(&self, name: &str, tag: &str) -> Result<()> {
        validate_tag(tag)?;
        self.check_exists(name)?;
        let _op = self.lock(name).await?;
        let vm_dir = self.paths.vm_dir(name);
        let file = state_file(&vm_dir, tag);
        // A RAM image without tags (a delete that failed halfway) still goes.
        let only_file = std::fs::symlink_metadata(&file).is_ok();
        let no_such = || anyhow::anyhow!("{name} has no snapshot named {tag}");
        match self.running(name) {
            Some(vm) => {
                let names = list_live(&vm.qmp).await?.1;
                if names.iter().any(|n| n == tag) {
                    delete(&vm.qmp, tag).await?;
                } else {
                    ensure!(only_file, no_such());
                }
            }
            None => {
                let names = names_offline(&vm_dir).await?;
                if all_names(&names).iter().any(|n| n == tag) {
                    delete_offline(&vm_dir, tag, &names).await?;
                } else {
                    ensure!(only_file, no_such());
                }
            }
        }
        safe_remove(&vm_dir, &file)?;
        Ok(())
    }
}

/// Whether `snap` was taken from a running guest (its clock ran) but its
/// RAM image is gone: restoring only the disk would revert to a
/// crash-consistent state without saying so. Disk-only snapshots of stopped
/// VMs have a guest clock of 0.
fn ram_missing(snap: &Snapshot) -> bool {
    snap.vm_clock_ms > 0 && snap.ram_bytes == 0
}

/// The name for a new snapshot, given the names in use: `tag` if it is
/// valid and free, else the next `snap<N>`. At most [`MAX_SNAPSHOTS`].
fn pick_new_name(names: &[String], tag: Option<&str>) -> Result<String> {
    ensure!(
        names.len() < MAX_SNAPSHOTS,
        "this VM has {MAX_SNAPSHOTS} snapshots, the most it may have; a human can delete one"
    );
    let Some(tag) = tag else {
        return Ok(next_name(names));
    };
    validate_tag(tag)?;
    ensure!(
        !names.iter().any(|n| n == tag),
        "a snapshot named {tag} already exists"
    );
    Ok(tag.to_owned())
}

/// Snapshot `tag` of VM `vm`, or the newest one.
fn pick_existing(list: &[Snapshot], vm: &str, tag: Option<&str>) -> Result<Snapshot> {
    let found = match tag {
        Some(t) => {
            validate_tag(t)?;
            list.iter().find(|s| s.name == t)
        }
        None => list.last(),
    };
    match (found, tag) {
        (Some(s), _) => Ok(s.clone()),
        (None, Some(t)) => bail!("{vm} has no snapshot named {t}; see `stallo snaps {vm}`"),
        (None, None) => bail!("{vm} has no snapshots; take one with `stallo snap {vm}`"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    fn raw(name: &str, ram: u64, sec: u64, nsec: u64) -> Value {
        json!({"id": "1", "name": name, "vm-state-size": ram, "date-sec": sec,
            "date-nsec": nsec, "vm-clock-sec": 12, "vm-clock-nsec": 345_678_901})
    }

    #[test]
    fn lists_are_parsed_sorted_and_filtered() {
        let v = json!([
            raw("b", 0, 20, 0),
            raw("a", 1 << 30, 10, 5),
            raw("c", 7, 10, 9),
            raw("1", 0, 1, 0),
            raw("bad\nname", 0, 1, 0),
            raw(&"x".repeat(65), 0, 1, 0),
        ]);
        let list = parse_list(v).unwrap();
        let names: Vec<&str> = list.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["a", "c", "b"]);
        assert_eq!(list[0].vm_clock_ms, 12_345);
        assert_eq!(list[2].created, 20);
        assert!(parse_list(Value::Null).unwrap().is_empty());
        assert!(parse_list(json!([{"name": "a"}])).is_err());
        assert!(parse_list(json!("x")).is_err());
    }

    #[test]
    fn names() {
        let list = parse_list(json!([raw("snap1", 0, 1, 0), raw("snap3", 0, 2, 0)])).unwrap();
        let names: Vec<String> = list.iter().map(|s| s.name.clone()).collect();
        assert_eq!(next_name(&names), "snap2");
        assert_eq!(next_name(&[]), "snap1");
        assert_eq!(pick_new_name(&names, None).unwrap(), "snap2");
        assert_eq!(pick_new_name(&names, Some("before")).unwrap(), "before");
        assert!(pick_new_name(&names, Some("snap1")).is_err());
        assert!(pick_new_name(&names, Some("-x")).is_err());
        let full: Vec<String> = (0..MAX_SNAPSHOTS).map(|i| format!("s{i}")).collect();
        let err = pick_new_name(&full, Some("more")).unwrap_err();
        assert!(err.to_string().contains("the most it may have"), "{err}");
        assert_eq!(pick_existing(&list, "dev", None).unwrap().name, "snap3");
        assert_eq!(
            pick_existing(&list, "dev", Some("snap1")).unwrap().name,
            "snap1"
        );
        let err = pick_existing(&list, "dev", Some("nope")).unwrap_err();
        assert!(err.to_string().contains("no snapshot named nope"));
        assert!(pick_existing(&[], "dev", None).is_err());
        assert!(pick_existing(&list, "dev", Some("../x")).is_err());
        // raw() has a running guest clock: without a RAM image it is broken.
        assert!(ram_missing(&list[0]));
        let disk_only = Snapshot {
            vm_clock_ms: 0,
            ..list[0].clone()
        };
        assert!(!ram_missing(&disk_only));
        let with_ram = Snapshot {
            ram_bytes: 1,
            ..list[0].clone()
        };
        assert!(!ram_missing(&with_ram));
    }

    /// How the fake QEMU behaves.
    #[derive(Clone, Default)]
    struct Script {
        /// Run state before the job.
        status: &'static str,
        /// The job pauses and (if it ran before) resumes the guest itself.
        resumes: bool,
        /// The job fails with this message.
        error: Option<&'static str>,
        /// No job events at all: the client must poll.
        silent: bool,
        /// The job never concludes.
        stuck: bool,
        /// `query-jobs` answers this late (QEMU's main loop is busy).
        jobs_delay: Duration,
        /// `blockdev-add` fails.
        no_add: bool,
    }

    /// A fake QEMU that runs `script` for every snapshot job and records
    /// every command it gets.
    async fn fake(script: Script) -> (tempfile::TempDir, Qmp, Arc<Mutex<Vec<String>>>) {
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
            let mut status = script.status;
            let mut job = json!(null);
            while let Ok(Some(line)) = lines.next_line().await {
                let req: Value = serde_json::from_str(&line).unwrap();
                let cmd = req["execute"].as_str().unwrap().to_owned();
                seen.lock().unwrap().push(cmd.clone());
                let mut events = Vec::new();
                let ret = match cmd.as_str() {
                    "qmp_capabilities" => json!({}),
                    "query-status" => json!({"status": status}),
                    "cont" => {
                        status = "running";
                        json!({})
                    }
                    "stop" => {
                        status = "paused";
                        json!({})
                    }
                    "query-jobs" => {
                        tokio::time::sleep(script.jobs_delay).await;
                        json!([job])
                    }
                    "blockdev-add" if script.no_add => {
                        let e = json!({"error": {"class": "GenericError", "desc": "no"}, "id": req["id"]});
                        w.write_all(format!("{e}\n").as_bytes()).await.unwrap();
                        continue;
                    }
                    "blockdev-add" => {
                        assert_eq!(req["arguments"]["node-name"], VMSTATE);
                        assert!(req["arguments"]["backing"].is_null());
                        assert!(req["arguments"].get("backing").is_some());
                        // QEMU's default cache: page cache with flushes
                        // (docs/ram-snapshot-io.md).
                        assert!(req["arguments"].get("cache").is_none());
                        assert_eq!(req["arguments"]["file"]["filename"], "/x/s1.qcow2");
                        json!({})
                    }
                    "blockdev-del" => json!({}),
                    "job-dismiss" => {
                        assert_eq!(req["arguments"]["id"], job["id"]);
                        json!({})
                    }
                    c if c.starts_with("snapshot-") => {
                        let id = req["arguments"]["job-id"].clone();
                        let st = if script.stuck { "running" } else { "concluded" };
                        job = json!({"id": id, "status": st});
                        if let Some(e) = script.error {
                            job["error"] = e.into();
                        }
                        let change = |s: &str| {
                            json!({"event": "JOB_STATUS_CHANGE",
                            "data": {"id": id, "status": s}})
                        };
                        if !script.silent {
                            events.push(change("created"));
                            events.push(change("running"));
                        }
                        if c != "snapshot-delete" && status == "running" {
                            events.push(json!({"event": "STOP", "data": {},
                                "timestamp": {"seconds": 100, "microseconds": 999_000}}));
                            status = "paused";
                            if script.resumes {
                                events.push(json!({"event": "RESUME", "data": {},
                                    "timestamp": {"seconds": 102, "microseconds": 1_000}}));
                                status = "running";
                            }
                        }
                        if !script.silent && !script.stuck {
                            events.push(change("concluded"));
                        }
                        json!({})
                    }
                    other => panic!("unexpected {other}"),
                };
                let reply = json!({"return": ret, "id": req["id"]});
                w.write_all(format!("{reply}\n").as_bytes()).await.unwrap();
                for e in events {
                    w.write_all(format!("{e}\n").as_bytes()).await.unwrap();
                }
            }
        });
        let qmp = Qmp::connect(&path, Duration::from_secs(5)).await.unwrap();
        (dir, qmp, log)
    }

    const F_PATH: &str = "/x/s1.qcow2";

    fn cmds(log: &Mutex<Vec<String>>) -> Vec<String> {
        log.lock()
            .unwrap()
            .iter()
            .filter(|c| !matches!(c.as_str(), "query-status" | "qmp_capabilities"))
            .cloned()
            .collect()
    }

    #[tokio::test]
    async fn save_measures_the_pause_and_dismisses_the_job() {
        let hold = AtomicBool::new(false);
        let (_d, qmp, log) = fake(Script {
            status: "running",
            resumes: true,
            ..Script::default()
        })
        .await;
        let pause = save(&qmp, "s1", Path::new(F_PATH), &hold).await.unwrap();
        assert_eq!(
            pause,
            Some(Duration::from_millis(1002)),
            "from QEMU's times"
        );
        assert_eq!(
            cmds(&log),
            [
                "blockdev-del",
                "blockdev-add",
                "snapshot-save",
                "query-jobs",
                "job-dismiss",
                "blockdev-del"
            ],
            "the RAM image is attached for the job only; no cont: QEMU resumed the guest"
        );
    }

    #[tokio::test]
    async fn a_guest_left_paused_is_continued_unless_held() {
        let hold = AtomicBool::new(false);
        let (_d, qmp, log) = fake(Script {
            status: "running",
            ..Script::default()
        })
        .await;
        let loaded = load(&qmp, "s1", Path::new(F_PATH), true, &hold)
            .await
            .unwrap();
        assert!(loaded.continued && loaded.pause.is_none());
        assert_eq!(cmds(&log).last().unwrap(), "cont");

        // A guest started paused (-S) is continued too.
        let (_d, qmp, log) = fake(Script {
            status: "prelaunch",
            ..Script::default()
        })
        .await;
        assert!(
            load(&qmp, "s1", Path::new(F_PATH), true, &hold)
                .await
                .unwrap()
                .continued
        );
        assert_eq!(cmds(&log).last().unwrap(), "cont");

        // Paused by the disk watchdog: stays paused.
        hold.store(true, Ordering::Relaxed);
        let (_d, qmp, log) = fake(Script {
            status: "running",
            ..Script::default()
        })
        .await;
        assert!(
            !load(&qmp, "s1", Path::new(F_PATH), true, &hold)
                .await
                .unwrap()
                .continued
        );
        assert!(save(&qmp, "s2", Path::new(F_PATH), &hold).await.is_ok());
        assert!(!cmds(&log).contains(&"cont".to_owned()));
    }

    #[tokio::test]
    async fn job_errors_are_reported_and_cleaned() {
        let hold = AtomicBool::new(false);
        let (_d, qmp, log) = fake(Script {
            status: "running",
            resumes: true,
            error: Some("Device 'disk0' is full\n\u{1b}[0m"),
            ..Script::default()
        })
        .await;
        let err = save(&qmp, "s1", Path::new(F_PATH), &hold)
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(err, "snapshot-save failed: Device 'disk0' is full[0m");
        let seen = cmds(&log);
        assert!(seen.contains(&"job-dismiss".to_owned()));
        assert_eq!(
            seen.last().unwrap(),
            "blockdev-del",
            "detached after a failure too"
        );
        assert!(delete(&qmp, "s1").await.is_err());

        // An image that cannot be attached: no job starts.
        let (_d, qmp, log) = fake(Script {
            status: "running",
            no_add: true,
            ..Script::default()
        })
        .await;
        assert!(save(&qmp, "s1", Path::new(F_PATH), &hold).await.is_err());
        assert!(!cmds(&log).iter().any(|c| c.starts_with("snapshot-")));
    }

    #[tokio::test]
    async fn missed_events_fall_back_to_polling() {
        let (_d, qmp, log) = fake(Script {
            status: "paused",
            silent: true,
            ..Script::default()
        })
        .await;
        delete(&qmp, "s1").await.unwrap();
        assert_eq!(
            cmds(&log),
            ["snapshot-delete", "query-jobs", "query-jobs", "job-dismiss"]
        );
    }

    #[tokio::test]
    async fn one_budget_for_slow_replies_and_stuck_jobs() {
        // A poll answered later than the poll interval is still waited for.
        let (_d, qmp, _) = fake(Script {
            status: "paused",
            silent: true,
            jobs_delay: Duration::from_millis(1500),
            ..Script::default()
        })
        .await;
        let args = json!({"tag": "s1", "devices": DEVICES});
        let job = run_job(
            &qmp,
            "snapshot-delete",
            args.clone(),
            Duration::from_secs(10),
        );
        assert!(job.await.is_ok());
        // A job that never ends fails at the deadline.
        let (_d, qmp, log) = fake(Script {
            status: "paused",
            stuck: true,
            ..Script::default()
        })
        .await;
        let started = Instant::now();
        let err = run_job(&qmp, "snapshot-delete", args, Duration::from_millis(1500))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("did not finish"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(3));
        assert!(!cmds(&log).contains(&"job-dismiss".to_owned()));
    }

    fn qemu_img_create(args: &[&str]) {
        let ok = std::process::Command::new("qemu-img")
            .args(["create", "-q", "-f", "qcow2"])
            .args(args)
            .status()
            .unwrap()
            .success();
        assert!(ok);
    }

    /// A stopped VM's files: the disk names a backing file that does not
    /// exist, so any use of it would fail.
    fn offline_vm(dir: &Path) {
        let disk = dir.join(qemu::DISK);
        let disk = disk.to_str().unwrap();
        qemu_img_create(&[
            "-u",
            "-F",
            "qcow2",
            "-b",
            "/nonexistent/base.qcow2",
            disk,
            "1G",
        ]);
        qemu_img_create(&[dir.join(qemu::VARS).to_str().unwrap(), "1M"]);
    }

    #[tokio::test]
    async fn offline_snapshots_never_open_a_backing_file() {
        if !confine::available() {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let dir = std::fs::canonicalize(tmp.path()).unwrap();
        offline_vm(&dir);
        assert!(list_offline(&dir).await.unwrap().is_empty());
        create_offline(&dir, "s1").await.unwrap();
        create_offline(&dir, "s2").await.unwrap();
        let list = list_offline(&dir).await.unwrap();
        let names = all_names(&names_offline(&dir).await.unwrap());
        let got: Vec<(&str, u64)> = list
            .iter()
            .map(|s| (s.name.as_str(), s.ram_bytes))
            .collect();
        assert_eq!(got, [("s1", 0), ("s2", 0)]);
        assert_eq!(names, ["s1", "s2"]);
        let per_image = names_offline(&dir).await.unwrap();
        apply_offline(&dir, "s1", &per_image).await.unwrap();
        delete_offline(&dir, "s1", &per_image).await.unwrap();
        let per_image = names_offline(&dir).await.unwrap();
        assert_eq!(per_image, [["s2"], ["s2"]]);
        assert!(apply_offline(&dir, "s1", &per_image).await.is_err());
        // The disk still names its backing file (the VM must still boot).
        let out = std::process::Command::new("qemu-img")
            .args(["info", "-f", "qcow2", "--output=json"])
            .arg(dir.join(qemu::DISK))
            .output()
            .unwrap();
        let info: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(info["backing-filename"], "/nonexistent/base.qcow2");
        // An incomplete snapshot is not applied.
        let partial = [vec!["s2".to_owned()], vec![]];
        let err = apply_offline(&dir, "s2", &partial).await.unwrap_err();
        assert!(err.to_string().contains("incomplete"), "{err}");

        // Firmware variables that cannot take the snapshot: the disk does
        // not keep it either.
        std::fs::write(dir.join(qemu::VARS), b"not qcow2").unwrap();
        assert!(create_offline(&dir, "s3").await.is_err());
        let files = offline_files(&dir);
        let snaps = image_snapshots(&files[0], &files).await.unwrap();
        assert!(snaps.iter().all(|s| s.name != "s3"));
    }

    #[test]
    fn ram_sizes_come_from_the_ram_images() {
        let tmp = tempfile::tempdir().unwrap();
        let states = tmp.path().join(qemu::STATES);
        std::fs::create_dir(&states).unwrap();
        std::fs::write(states.join("a.qcow2"), vec![1; 8192]).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", states.join("c.qcow2")).unwrap();
        let list = parse_list(json!([
            raw("a", 0, 1, 0),
            raw("b", 0, 2, 0),
            raw("c", 0, 3, 0)
        ]));
        let list = with_ram(list.unwrap(), tmp.path());
        let ram: Vec<u64> = list.iter().map(|s| s.ram_bytes).collect();
        assert_eq!(ram, [8192, 0, 0], "a symlink is not a RAM image");
        assert_eq!(state_file(tmp.path(), "a"), states.join("a.qcow2"));
    }

    #[tokio::test]
    async fn qemu_img_is_confined_to_the_vm_files() {
        if !confine::available() {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let dir = std::fs::canonicalize(tmp.path()).unwrap();
        let (own, other) = (dir.join("own"), dir.join("other"));
        std::fs::create_dir(&own).unwrap();
        std::fs::create_dir(&other).unwrap();
        offline_vm(&own);
        offline_vm(&other);
        let files = offline_files(&own);
        let other_disk = other.join(qemu::DISK);
        assert!(qemu_img(&["info"], &files[0], &files).await.is_ok());
        let err = qemu_img(&["info"], &other_disk, &files).await.unwrap_err();
        assert!(format!("{err:#}").contains("Permission denied"), "{err:#}");
        assert!(
            qemu_img(&["snapshot", "-c", "x"], &other_disk, &files)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn live_list_reads_the_disk_node() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("qmp.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            let (r, mut w) = s.into_split();
            let mut lines = BufReader::new(r).lines();
            w.write_all(b"{\"QMP\": {}}\n").await.unwrap();
            while let Ok(Some(line)) = lines.next_line().await {
                let req: Value = serde_json::from_str(&line).unwrap();
                let ret = if req["execute"] == "query-named-block-nodes" {
                    assert_eq!(req["arguments"]["flat"], true);
                    json!([
                        {"node-name": "disk0", "image": {"snapshots": [raw("s1", 0, 1, 0)]}},
                        {"node-name": "base", "image": {"snapshots": [raw("y", 0, 1, 0)]}},
                        {"node-name": "fw-vars", "image": {"snapshots": [raw("x", 0, 1, 0)]}},
                    ])
                } else {
                    json!({})
                };
                let reply = json!({"return": ret, "id": req["id"]});
                w.write_all(format!("{reply}\n").as_bytes()).await.unwrap();
            }
        });
        let qmp = Qmp::connect(&path, Duration::from_secs(5)).await.unwrap();
        let (list, names) = list_live(&qmp).await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "s1");
        assert_eq!(
            names,
            ["s1", "x"],
            "a leftover on fw-vars counts, other nodes not"
        );
    }
}
