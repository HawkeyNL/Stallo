//! Snapshots: internal qcow2 snapshots of a VM's disk and firmware
//! variables.
//!
//! A stopped VM gets disk-only snapshots through `qemu-img` (confined like
//! QEMU). A running VM is snapshotted with QMP jobs (`snapshot-save`, `-load`,
//! `-delete`). Its RAM ("vmstate") is written to the `state` image, and
//! the guest is paused meanwhile (see [`crate::qemu::create_state`] for why
//! RAM has an image of its own). Every snapshot covers all three writable
//! nodes, `disk0`, `fw-vars` and `state`, so firmware variables always
//! match the disk.
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
use crate::qmp::Qmp;
use crate::vm::{Manager, QGA_BUSY_WAIT, Running};
use crate::{cgroup, confine, host, qemu};

/// The block nodes in every snapshot (named in `qemu::argv`).
const DEVICES: [&str; 3] = ["disk0", "fw-vars", VMSTATE];
/// The node that stores the RAM, and whose snapshot list is the VM's.
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
    /// Bytes of saved RAM; 0 for a disk-only snapshot.
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
    #[serde(rename = "vm-state-size")]
    vm_state_size: u64,
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
/// Stallo would never create are dropped.
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
            ram_bytes: s.vm_state_size,
            created: s.date_sec,
            vm_clock_ms: s
                .vm_clock_sec
                .saturating_mul(1000)
                .saturating_add(s.vm_clock_nsec / 1_000_000),
        })
        .collect())
}

/// The first free name of the form `snap<N>`.
pub fn next_name(names: &[String]) -> String {
    (1..)
        .map(|n| format!("snap{n}"))
        .find(|t| !names.contains(t))
        .expect("a free name exists")
}

/// A running VM's snapshots (from the `state` node), and every snapshot
/// name in use on any of its nodes: a save that failed halfway can leave a
/// name on `disk0` or `fw-vars` only, and QEMU refuses to reuse it.
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
        let is_state = n == VMSTATE;
        let snaps = parse_list(node["image"]["snapshots"].take())?;
        names.extend(snaps.iter().map(|s| s.name.clone()));
        if is_state {
            list = Some(snaps);
        }
    }
    names.sort();
    names.dedup();
    let list = list.context("QEMU did not report the snapshot state image")?;
    Ok((list, names))
}

/// Saves the running VM's disk, firmware variables and RAM as `tag`. Returns
/// how long the guest was paused. QEMU resumes the guest itself; if it does
/// not, `cont` follows unless `hold` is set.
pub async fn save(qmp: &Qmp, tag: &str, hold: &AtomicBool) -> Result<Option<Duration>> {
    let was_running = status(qmp).await? == "running";
    let args = json!({"tag": tag, "vmstate": VMSTATE, "devices": DEVICES});
    let pause = run_job(qmp, "snapshot-save", args, JOB_TIMEOUT).await?;
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

/// Loads `tag` (disk, firmware variables and RAM). With `run`, the guest
/// runs afterwards: QEMU resumes a guest that ran before the load, and
/// `cont` covers the rest (a guest started paused), unless `hold` is set.
pub async fn load(qmp: &Qmp, tag: &str, run: bool, hold: &AtomicBool) -> Result<Loaded> {
    let args = json!({"tag": tag, "vmstate": VMSTATE, "devices": DEVICES});
    let pause = run_job(qmp, "snapshot-load", args, JOB_TIMEOUT).await?;
    let continued = run && cont_unless_held(qmp, hold).await?;
    Ok(Loaded { pause, continued })
}

/// Deletes `tag` from every node that has it.
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

/// The files of a stopped VM that hold snapshots, in [`DEVICES`] order.
fn offline_files(vm_dir: &Path) -> [PathBuf; 3] {
    [qemu::DISK, qemu::VARS, qemu::STATE].map(|f| vm_dir.join(f))
}

const QEMU_IMG: &str = "/usr/bin/qemu-img";

/// `qemu-img` on a stopped VM's own files. A compromised QEMU may have
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

/// A stopped VM's snapshots (from `state.qcow2`). A VM that has not started
/// since snapshots existed has no state image and no snapshots.
pub async fn list_offline(vm_dir: &Path) -> Result<Vec<Snapshot>> {
    let files = offline_files(vm_dir);
    if !files[2].exists() {
        return Ok(Vec::new());
    }
    image_snapshots(&files[2], &files).await
}

/// The snapshot names in each image of a stopped VM ([`DEVICES`] order).
/// They differ only after a failure.
pub async fn names_offline(vm_dir: &Path) -> Result<[Vec<String>; 3]> {
    let files = offline_files(vm_dir);
    let mut names: [Vec<String>; 3] = Default::default();
    if files[2].exists() {
        for (f, n) in files.iter().zip(&mut names) {
            *n = image_snapshots(f, &files)
                .await?
                .into_iter()
                .map(|s| s.name)
                .collect();
        }
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

/// Takes a disk-only snapshot of a stopped VM: `tag` on all three images,
/// or on none (a failure removes it again).
pub async fn create_offline(vm_dir: &Path, tag: &str) -> Result<()> {
    let files = offline_files(vm_dir);
    // VMs created before snapshots existed have no state image yet.
    if !files[2].exists() {
        qemu::create_state(&files[2]).await?;
    }
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
/// not used). Refused unless all three images have it, so a restore never
/// stops halfway for that reason.
pub async fn apply_offline(vm_dir: &Path, tag: &str, names: &[Vec<String>; 3]) -> Result<()> {
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
pub async fn delete_offline(vm_dir: &Path, tag: &str, names: &[Vec<String>; 3]) -> Result<()> {
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
        let _op = self.lock(name).await;
        let vm = self.running(name);
        let names = match &vm {
            Some(vm) => list_live(&vm.qmp).await?.1,
            None => all_names(&names_offline(&self.paths.vm_dir(name)).await?),
        };
        let tag = pick_new_name(&names, tag)?;
        let ram = vm.as_ref().map_or(0, |vm| vm.config.memory_mib << 20);
        host::check_snapshot_space(
            host::disk_free(&self.paths.data)?,
            self.config.host.disk_floor_gib,
            ram,
        )?;
        let pause = match &vm {
            Some(vm) => save(&vm.qmp, &tag, &vm.disk_full).await?,
            None => {
                create_offline(&self.paths.vm_dir(name), &tag).await?;
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
        let _op = self.lock(name).await;
        Ok(match self.running(name) {
            Some(vm) => list_live(&vm.qmp).await?.0,
            None => list_offline(&self.paths.vm_dir(name)).await?,
        })
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
        let _op = self.lock(name).await;
        let vm_dir = self.paths.vm_dir(name);
        let (vm, list) = match self.running(name) {
            Some(vm) => {
                let list = list_live(&vm.qmp).await?.0;
                (Some(vm), list)
            }
            None => (None, list_offline(&vm_dir).await?),
        };
        let snap = pick_existing(&list, name, tag)?;
        let pause = match vm {
            Some(vm) => {
                ensure!(
                    snap.ram_bytes > 0,
                    "{} has no RAM state; stop the VM first, then restore it: stallo stop {name}",
                    snap.name
                );
                let run = vm.status().await? == "running";
                self.load_into(&vm, &snap.name, run).await?
            }
            None if snap.ram_bytes > 0 => {
                // Not `-loadvm`: it looks for the RAM on the first image
                // that has the snapshot (the firmware variables) and fails.
                let vm = self.start_locked(name, true).await?;
                match self.load_into(&vm, &snap.name, true).await {
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

    /// Loads RAM snapshot `tag` into the running QEMU of `vm` and drops the
    /// kept guest-agent connection. Returns how long the guest was paused.
    async fn load_into(&self, vm: &Running, tag: &str, run: bool) -> Result<Option<Duration>> {
        // No guest-agent operation may straddle the load.
        let mut agent = tokio::time::timeout(QGA_BUSY_WAIT, vm.qga.lock())
            .await
            .map_err(|_| {
                anyhow::anyhow!("{} is busy with a guest command; try again", vm.config.name)
            })?;
        let loaded = load(&vm.qmp, tag, run, &vm.disk_full).await;
        *agent = None;
        let loaded =
            loaded.with_context(|| format!("cannot restore {tag}; the VM may be left paused"))?;
        tracing::debug!("{}: loaded {tag}: {loaded:?}", vm.config.name);
        Ok(loaded.pause)
    }

    /// Deletes snapshot `tag`, also one that a failed save left on some
    /// images only.
    pub async fn delete_snapshot(&self, name: &str, tag: &str) -> Result<()> {
        validate_tag(tag)?;
        self.check_exists(name)?;
        let _op = self.lock(name).await;
        let vm_dir = self.paths.vm_dir(name);
        let vm = self.running(name);
        let no_such = || anyhow::anyhow!("{name} has no snapshot named {tag}");
        match vm {
            Some(vm) => {
                let names = list_live(&vm.qmp).await?.1;
                ensure!(names.iter().any(|n| n == tag), no_such());
                delete(&vm.qmp, tag).await
            }
            None => {
                let names = names_offline(&vm_dir).await?;
                ensure!(all_names(&names).iter().any(|n| n == tag), no_such());
                delete_offline(&vm_dir, tag, &names).await
            }
        }
    }
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
        assert_eq!(list[0].ram_bytes, 1 << 30);
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
        let pause = save(&qmp, "s1", &hold).await.unwrap();
        assert_eq!(
            pause,
            Some(Duration::from_millis(1002)),
            "from QEMU's times"
        );
        assert_eq!(
            cmds(&log),
            ["snapshot-save", "query-jobs", "job-dismiss"],
            "no cont: QEMU resumed the guest"
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
        let loaded = load(&qmp, "s1", true, &hold).await.unwrap();
        assert!(loaded.continued && loaded.pause.is_none());
        assert_eq!(cmds(&log).last().unwrap(), "cont");

        // A guest started paused (-S) is continued too.
        let (_d, qmp, log) = fake(Script {
            status: "prelaunch",
            ..Script::default()
        })
        .await;
        assert!(load(&qmp, "s1", true, &hold).await.unwrap().continued);
        assert_eq!(cmds(&log).last().unwrap(), "cont");

        // Paused by the disk watchdog: stays paused.
        hold.store(true, Ordering::Relaxed);
        let (_d, qmp, log) = fake(Script {
            status: "running",
            ..Script::default()
        })
        .await;
        assert!(!load(&qmp, "s1", true, &hold).await.unwrap().continued);
        assert!(save(&qmp, "s2", &hold).await.is_ok());
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
        let err = save(&qmp, "s1", &hold).await.unwrap_err().to_string();
        assert_eq!(err, "snapshot-save failed: Device 'disk0' is full[0m");
        assert!(cmds(&log).contains(&"job-dismiss".to_owned()));
        assert!(delete(&qmp, "s1").await.is_err());
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
        qemu_img_create(&[dir.join(qemu::STATE).to_str().unwrap(), "2M"]);
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
        assert_eq!(per_image, [["s2"], ["s2"], ["s2"]]);
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
        let partial = [vec!["s2".to_owned()], vec![], vec!["s2".to_owned()]];
        let err = apply_offline(&dir, "s2", &partial).await.unwrap_err();
        assert!(err.to_string().contains("incomplete"), "{err}");

        // A state image that cannot take the snapshot: none of the images
        // keeps it.
        std::fs::write(dir.join(qemu::STATE), b"not qcow2").unwrap();
        assert!(create_offline(&dir, "s3").await.is_err());
        let files = offline_files(&dir);
        for f in &files[..2] {
            let snaps = image_snapshots(f, &files).await.unwrap();
            assert!(snaps.iter().all(|s| s.name != "s3"), "{}", f.display());
        }

        // A VM without a state image (made before snapshots existed).
        std::fs::remove_file(dir.join(qemu::STATE)).unwrap();
        assert_eq!(
            names_offline(&dir).await.unwrap(),
            <[Vec<String>; 3]>::default()
        );
        create_offline(&dir, "s4").await.unwrap();
        assert_eq!(list_offline(&dir).await.unwrap()[0].name, "s4");
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
    async fn live_list_reads_the_state_node() {
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
                        {"node-name": "disk0", "image": {"snapshots": [raw("x", 0, 1, 0)]}},
                        {"node-name": "base", "image": {"snapshots": [raw("y", 0, 1, 0)]}},
                        {"node-name": "state", "image": {"snapshots": [raw("s1", 9, 1, 0)]}},
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
            "a leftover on disk0 counts, other nodes not"
        );
    }
}
