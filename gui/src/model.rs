//! Plain-Rust view-model: what the window should show, decided from facts
//! gathered elsewhere (no GTK, no I/O), so every case is unit-testable.

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use stallo::api::{Request, VmDetails, VmInfo};
use stallo::config::NetProfile;
use stallo::host::HostInfo;
use stallo::printable;
use stallo::snapshot::Snapshot;

/// How often the window probes again while it shows an onboarding page.
pub const POLL: Duration = Duration::from_secs(5);

/// The production API socket as seen by this user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Production {
    /// The socket exists and its directory is open to us.
    Up,
    /// No socket (or no `/run/stallo`): the service is not running.
    Missing,
    /// `/run/stallo` exists but is closed to us (EACCES): not in the group.
    Denied,
}

/// Why a request to the daemon failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallError {
    /// ENOENT or ECONNREFUSED: nothing listens on the socket.
    NotRunning,
    /// EACCES on the socket or its directory.
    Denied,
    /// No answer in time.
    Timeout,
    /// Anything else, with the (untrusted) message.
    Failed(String),
}

/// Group `stallo` as far as this user is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Group {
    /// The user is listed in group `stallo` in /etc/group.
    pub listed: bool,
    /// This process already has the group (getgroups()).
    pub active: bool,
}

/// Everything local and root-free the window knows about the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    /// `/dev/kvm` exists.
    pub kvm: bool,
    /// `$STALLO_SOCKET`, which overrides the choice below.
    pub explicit: Option<PathBuf>,
    pub production: Production,
    /// The dev-mode socket path, when HOME and XDG_RUNTIME_DIR allow one.
    pub dev: Option<PathBuf>,
    /// The dev-mode socket exists.
    pub dev_up: bool,
    pub group: Group,
    /// The result of `list` on [`socket`]'s choice: the VM count.
    pub list: Option<Result<usize, CallError>>,
}

/// What the window shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Onboarding {
    NoKvm,
    DaemonStopped,
    NotInGroup,
    NeedsRelogin,
    TwoDaemons {
        dev: PathBuf,
    },
    /// Nothing answers on the socket from `$STALLO_SOCKET`. Starting the
    /// system service would not help: it may be another daemon.
    SocketDown {
        socket: PathBuf,
    },
    /// The daemon is there but the request failed (timeout, error reply).
    Unreachable(String),
    /// The daemon on `socket` answered.
    Connected {
        socket: PathBuf,
    },
}

/// The socket to send `list` to, or `None` when the probe already decides
/// the state: `$STALLO_SOCKET`, else the CLI's choice (`pick_socket`).
pub fn socket(p: &Probe) -> Option<PathBuf> {
    if !p.kvm {
        return None;
    }
    if let Some(s) = &p.explicit {
        return Some(s.clone());
    }
    let production = stallo::paths::Paths::production().ok()?.api_socket();
    stallo::paths::pick_socket(
        (p.production == Production::Up).then_some(production),
        p.dev
            .clone()
            .ok_or_else(|| anyhow::anyhow!("no dev-mode socket")),
        p.dev_up,
        p.production == Production::Denied,
    )
    .ok()
}

/// Whether this process may hand its window to an already running one.
/// Not when `$STALLO_SOCKET` is set: that instance must talk to the chosen
/// daemon, and must not take over plain launches from the app menu.
pub fn single_instance(stallo_socket_set: bool) -> bool {
    !stallo_socket_set
}

pub fn onboarding(p: &Probe) -> Onboarding {
    if !p.kvm {
        return Onboarding::NoKvm;
    }
    let denied = || match p.group {
        // In the group and still refused: not a membership problem.
        Group { active: true, .. } => Onboarding::Unreachable("permission denied".into()),
        Group { listed: false, .. } => Onboarding::NotInGroup,
        _ => Onboarding::NeedsRelogin,
    };
    let Some(socket) = socket(p) else {
        // Why the CLI's choice refused (or found nothing).
        return match (p.production, &p.dev) {
            (Production::Up, Some(dev)) if p.dev_up => Onboarding::TwoDaemons { dev: dev.clone() },
            (Production::Denied, _) => denied(),
            _ => Onboarding::DaemonStopped,
        };
    };
    match &p.list {
        Some(Err(CallError::NotRunning)) | None if p.explicit.is_some() => {
            Onboarding::SocketDown { socket }
        }
        Some(Ok(_)) => Onboarding::Connected { socket },
        Some(Err(CallError::Denied)) => denied(),
        Some(Err(CallError::Timeout)) => Onboarding::Unreachable("no answer in time".into()),
        Some(Err(CallError::Failed(e))) => Onboarding::Unreachable(e.clone()),
        Some(Err(CallError::NotRunning)) | None => Onboarding::DaemonStopped,
    }
}

/// Whether the user is listed in group `stallo` in /etc/group (`etc_group`
/// is its text), and whether this process has that group already.
pub fn group(etc_group: &str, user: &str, gids: &[u32]) -> Group {
    let Some((gid, members)) = etc_group.lines().find_map(|l| {
        let mut f = l.split(':');
        (f.next() == Some("stallo")).then_some(())?;
        let gid = f.nth(1)?.parse::<u32>().ok()?;
        Some((gid, f.next().unwrap_or("")))
    }) else {
        return Group::default();
    };
    Group {
        // An unset $USER must never match an empty member.
        listed: !user.is_empty() && members.split(',').any(|m| m == user),
        active: gids.contains(&gid),
    }
}

/// What the window shows after a probe, given what it shows now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct View {
    pub page: Onboarding,
    /// Connected before, lost it: keep the page, show the banner.
    pub reconnecting: bool,
}

impl View {
    /// The next view, and whether to say the connection is back.
    pub fn next(&self, probed: Onboarding) -> (View, bool) {
        let was_connected = matches!(self.page, Onboarding::Connected { .. });
        let lost = matches!(
            probed,
            Onboarding::DaemonStopped | Onboarding::SocketDown { .. } | Onboarding::Unreachable(_)
        );
        if was_connected && lost {
            let view = View {
                page: self.page.clone(),
                reconnecting: true,
            };
            return (view, false);
        }
        let back = self.reconnecting && matches!(probed, Onboarding::Connected { .. });
        let view = View {
            page: probed,
            reconnecting: false,
        };
        (view, back)
    }

    /// Whether to probe every [`POLL`]: while the window is visible and not
    /// connected. Focus changes probe on their own.
    pub fn polls(&self, visible: bool) -> bool {
        visible && (self.reconnecting || !matches!(self.page, Onboarding::Connected { .. }))
    }

    /// Whether to poll the VM list and the host: while the window is
    /// visible and connected. While reconnecting the probe takes over.
    pub fn polls_vms(&self, visible: bool) -> bool {
        visible && !self.reconnecting && matches!(self.page, Onboarding::Connected { .. })
    }
}

impl fmt::Display for CallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CallError::NotRunning => f.write_str("Stallo is not running"),
            CallError::Denied => f.write_str("permission denied"),
            CallError::Timeout => f.write_str("no answer in time"),
            // From the daemon (and maybe the guest): never trusted.
            CallError::Failed(e) => f.write_str(&printable(e, 300)),
        }
    }
}

/// How often the VM list, the host and an open VM's details are asked for.
pub const LIST_EVERY: Duration = Duration::from_secs(3);
pub const HOST_EVERY: Duration = Duration::from_secs(15);
pub const INFO_EVERY: Duration = Duration::from_secs(10);
/// The wait after a failed poll.
pub const BACKOFF: Duration = Duration::from_secs(30);
/// How often the window checks which polls are due.
// ponytail: a 1 s heartbeat, so a poll runs up to 1 s late; the daemon's
// long-poll replaces list polling later.
pub const TICK: Duration = Duration::from_secs(1);

/// One repeated request: due every so often, never two at once.
#[derive(Debug, Clone)]
pub struct Poll {
    every: Duration,
    next: Option<Instant>,
    busy: bool,
    /// Asked for again while busy: the answer in flight may be too old.
    stale: bool,
}

impl Poll {
    pub fn new(every: Duration) -> Self {
        Self {
            every,
            next: None,
            busy: false,
            stale: false,
        }
    }

    /// Whether to send the request now; if so, it counts as sent.
    pub fn due(&mut self, now: Instant) -> bool {
        let due = !self.busy && self.next.is_none_or(|n| now >= n);
        self.busy |= due;
        due
    }

    /// The answer is back: wait `every`, or [`BACKOFF`] after an error.
    /// A stale answer asks again at the next tick (errors still back off).
    pub fn done(&mut self, now: Instant, ok: bool) {
        let again = ok && self.stale;
        self.busy = false;
        self.stale = false;
        self.next = match (again, ok) {
            (true, _) => None,
            (false, true) => Some(now + self.every),
            (false, false) => Some(now + BACKOFF),
        };
    }

    /// Ask at the next tick, e.g. after an action; if a request is out,
    /// once more after it.
    pub fn soon(&mut self) {
        if self.busy {
            self.stale = true;
        } else {
            self.next = None;
        }
    }
}

/// What a VM's state string means for the window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Stopped,
    Running,
    /// Paused, or another QEMU state on the way somewhere.
    Paused,
    /// Paused by the disk watchdog; a human resumes it.
    DiskFull,
    /// `io-error`, a crash, or QMP does not answer (`unknown`).
    Failed,
}

pub fn kind(state: &str) -> Kind {
    // "running (no network)" once the network of a VM was cut.
    match state.strip_suffix(" (no network)").unwrap_or(state) {
        "stopped" => Kind::Stopped,
        "running" => Kind::Running,
        "paused (disk full)" => Kind::DiskFull,
        "io-error" | "internal-error" | "guest-panicked" | "unknown" => Kind::Failed,
        _ => Kind::Paused,
    }
}

/// A VM in the sidebar. Strings are safe to show in plain labels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowVm {
    pub name: String,
    pub state: String,
    /// The libadwaita style class for the state, if any.
    pub tone: Option<&'static str>,
    pub control_icon: &'static str,
    pub control_tip: &'static str,
}

pub fn row(vm: &VmInfo) -> RowVm {
    let tone = match kind(&vm.state) {
        Kind::Stopped => None,
        Kind::Running => Some("success"),
        Kind::Paused | Kind::DiskFull => Some("warning"),
        Kind::Failed => Some("error"),
    };
    let (control_icon, control_tip) = if vm.agent_control {
        ("security-high-symbolic", "Agent control on")
    } else {
        ("avatar-default-symbolic", "Agent control off")
    };
    RowVm {
        name: printable(&vm.name, 64),
        state: printable(&vm.state, 64),
        tone,
        control_icon,
        control_tip,
    }
}

/// A lifecycle action on one VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Start,
    Stop,
    ForceOff,
    Reset,
    Resume,
}

impl Op {
    pub const ALL: [Op; 5] = [Op::Start, Op::Stop, Op::ForceOff, Op::Reset, Op::Resume];

    pub fn request(self, name: &str) -> Request {
        let name = name.to_owned();
        match self {
            // Not waiting for the guest agent: the window polls the state.
            Op::Start => Request::Start { name, wait: false },
            Op::Stop => Request::Stop { name, force: false },
            Op::ForceOff => Request::Stop { name, force: true },
            Op::Reset => Request::Reset { name },
            Op::Resume => Request::Resume { name },
        }
    }

    /// The time limit; a graceful stop alone may take 80 s in the daemon.
    pub fn limit(self) -> Duration {
        Duration::from_secs(150)
    }

    /// The action name in the window (`vm.<name>`).
    pub fn action(self) -> &'static str {
        match self {
            Op::Start => "start",
            Op::Stop => "stop",
            Op::ForceOff => "force-off",
            Op::Reset => "reset",
            Op::Resume => "resume",
        }
    }

    /// The toast when it fails.
    pub fn failed(self, vm: &str, e: &CallError) -> String {
        let what = match self {
            Op::Start => "start",
            Op::Stop => "stop",
            Op::ForceOff => "force off",
            Op::Reset => "reset",
            Op::Resume => "resume",
        };
        format!("Could not {what} {}: {e}", printable(vm, 64))
    }
}

/// The time limit of a snapshot action. The daemon gives the snapshot job
/// alone 600 s; around it, it waits for the VM's lock, may start the VM,
/// waits up to 10 s for the guest agent or stops the VM again. Also the
/// longest any action may take.
pub const SNAP_LIMIT: Duration = Duration::from_secs(900);

/// Anything that changes a VM: a lifecycle [`Op`] or a snapshot action.
/// Snapshot names are raw, as the daemon listed them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Life(Op),
    /// Takes a snapshot; the daemon picks a name if there is none.
    Take(Option<String>),
    Restore(String),
    Delete(String),
}

impl Action {
    pub fn request(&self, vm: &str) -> Request {
        let name = vm.to_owned();
        match self {
            Action::Life(op) => op.request(vm),
            Action::Take(tag) => Request::Snapshot {
                name,
                tag: tag.clone(),
            },
            Action::Restore(tag) => Request::Restore {
                name,
                tag: Some(tag.clone()),
            },
            Action::Delete(tag) => Request::SnapshotDelete {
                name,
                tag: tag.clone(),
            },
        }
    }

    pub fn limit(&self) -> Duration {
        match self {
            Action::Life(op) => op.limit(),
            _ => SNAP_LIMIT,
        }
    }

    /// The toast when it fails. A snapshot action that timed out may
    /// still run in the daemon.
    pub fn failed(&self, vm: &str, e: &CallError) -> String {
        let vm = printable(vm, 64);
        let (what, slow) = match self {
            Action::Life(op) => return op.failed(&vm, e),
            Action::Take(_) => (
                format!("take a snapshot of {vm}"),
                format!("The snapshot of {vm}"),
            ),
            Action::Restore(tag) => {
                let tag = printable(tag, 64);
                (format!("restore {tag}"), format!("Restoring {tag}"))
            }
            Action::Delete(tag) => {
                let tag = printable(tag, 64);
                (format!("delete {tag}"), format!("Deleting {tag}"))
            }
        };
        match e {
            CallError::Timeout => {
                format!("{slow} takes long and may still be running; check the list later")
            }
            _ => format!("Could not {what}: {e}"),
        }
    }

    /// The toast when it worked, given the daemon's answer. Snapshot
    /// actions may take minutes, so they say when they are done.
    pub fn done(&self, vm: &str, data: &serde_json::Value) -> Option<String> {
        let vm = printable(vm, 64);
        match self {
            Action::Life(_) => None,
            Action::Take(_) => Some(match data.get("name").and_then(|n| n.as_str()) {
                Some(n) => format!("Snapshot {} taken", printable(n, 64)),
                None => "Snapshot taken".to_owned(),
            }),
            Action::Restore(tag) => Some(format!("{vm} restored to {}", printable(tag, 64))),
            Action::Delete(tag) => Some(format!("Snapshot {} deleted", printable(tag, 64))),
        }
    }
}

/// Which actions a VM offers now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ActionSet {
    pub start: bool,
    pub stop: bool,
    pub force_off: bool,
    pub reset: bool,
    pub resume: bool,
    /// The VM exists as a process but does not run (paused, disk full,
    /// io-error...): Resume and Force Off take the place of Stop, which
    /// could not shut the guest down cleanly anyway.
    pub halted: bool,
}

impl ActionSet {
    pub fn allows(&self, op: Op) -> bool {
        match op {
            Op::Start => self.start,
            Op::Stop => self.stop,
            Op::ForceOff => self.force_off,
            Op::Reset => self.reset,
            Op::Resume => self.resume,
        }
    }
}

/// The actions for `vm`; none while `blocked`: one of its actions runs or
/// just ran, or the daemon is out of reach.
pub fn actions(vm: &VmInfo, blocked: bool) -> ActionSet {
    let k = kind(&vm.state);
    let running = k == Kind::Running;
    // The daemon stops a VM that does not run with a hard QMP quit.
    let halted = !running && k != Kind::Stopped;
    let set = ActionSet {
        start: k == Kind::Stopped,
        stop: running,
        force_off: running || halted,
        reset: running,
        resume: halted,
        halted,
    };
    if blocked {
        ActionSet {
            halted,
            ..ActionSet::default()
        }
    } else {
        set
    }
}

/// What to ask before an action that may lose data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Confirm {
    pub heading: String,
    pub body: String,
    pub button: &'static str,
}

/// The question before Force Off or Reset; `None` for other actions.
pub fn confirm(op: Op, vm: &VmInfo) -> Option<Confirm> {
    let button = match op {
        Op::ForceOff => "Force Off",
        Op::Reset => "Reset",
        _ => return None,
    };
    let mut body = String::new();
    if op == Op::ForceOff && kind(&vm.state) != Kind::Running {
        body.push_str("The VM does not run, so it cannot shut down cleanly. ");
    }
    body.push_str("Unsaved work in the VM is lost and its file systems may need repair.");
    Some(Confirm {
        heading: format!("{button} {}?", printable(&vm.name, 64)),
        body,
        button,
    })
}

/// VMs whose buttons stay off: while an action runs, and after it until
/// a VM list that was asked for after it ended arrives (no second Start
/// on a state from before the first).
#[derive(Debug, Default)]
pub struct Pending(HashMap<String, Option<Instant>>);

impl Pending {
    /// Claims `vm` for an action; false if it has one already.
    pub fn start(&mut self, vm: &str) -> bool {
        if self.0.contains_key(vm) {
            return false;
        }
        self.0.insert(vm.to_owned(), None);
        true
    }

    pub fn finish(&mut self, vm: &str, now: Instant) {
        if let Some(end) = self.0.get_mut(vm) {
            *end = Some(now);
        }
    }

    /// A VM list arrived that was asked for at `sent`.
    pub fn listed(&mut self, sent: Instant) {
        self.0.retain(|_, end| end.is_none_or(|end| end > sent));
    }

    pub fn blocks(&self, vm: &str) -> bool {
        self.0.contains_key(vm)
    }
}

/// Whether to ask for an open VM's details: while its page is visible and
/// it runs, and once for a stopped VM (disk use).
pub fn wants_info(page_visible: bool, kind: Kind, have: bool) -> bool {
    page_visible && (kind == Kind::Running || !have)
}

/// How often an open Snapshots tab asks for the list.
pub const SNAPS_EVERY: Duration = Duration::from_secs(15);

/// Whether the Snapshots tab leaves the daemon alone. `stuck` is the VM
/// state and time of a snapshot list that timed out: its connection may
/// still wait in the daemon for the VM's lock, behind a job of up to
/// [`SNAP_LIMIT`], and every new list would queue one more. So no new list
/// until the VM's state changes or that time is up.
pub fn snaps_wait(stuck: Option<&(String, Instant)>, state: &str, now: Instant) -> bool {
    stuck.is_some_and(|(s, at)| s == state && now < *at + SNAP_LIMIT)
}

/// One snapshot on the timeline. Display strings are safe for plain
/// labels; `tag` is the raw name to send back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapRow {
    pub tag: String,
    pub name: String,
    /// When it was taken, and the size of its saved memory.
    pub subtitle: String,
    /// It holds the VM's memory (RAM).
    pub memory: bool,
    /// Why it cannot be restored now, whatever else runs.
    pub restore_block: Option<&'static str>,
}

/// The timeline: newest first. `now` is the host clock in Unix seconds.
pub fn timeline(vm: &VmInfo, snaps: &[Snapshot], now: u64) -> Vec<SnapRow> {
    snaps
        .iter()
        .rev()
        .map(|s| {
            let mut subtitle = age(now.saturating_sub(s.created));
            if s.ram_bytes > 0 {
                subtitle.push_str(" · ");
                subtitle.push_str(&size(s.ram_bytes));
            }
            SnapRow {
                tag: s.name.clone(),
                name: printable(&s.name, 64),
                subtitle,
                memory: s.ram_bytes > 0,
                restore_block: restore_block(vm, s),
            }
        })
        .collect()
}

/// The daemon's restore rules, so the button is off where it would refuse.
fn restore_block(vm: &VmInfo, snap: &Snapshot) -> Option<&'static str> {
    if stallo::snapshot::ram_missing(snap) {
        Some("Its saved memory is missing, so it cannot be restored")
    } else if snap.ram_bytes == 0 && kind(&vm.state) != Kind::Stopped {
        Some("Stop the VM to restore a snapshot without memory")
    } else {
        None
    }
}

/// How long ago, in words.
fn age(secs: u64) -> String {
    let (n, unit) = match secs {
        0..60 => return "Just now".to_owned(),
        60..3600 => (secs / 60, "minute"),
        3600..86400 => (secs / 3600, "hour"),
        _ => (secs / 86400, "day"),
    };
    let s = if n == 1 { "" } else { "s" };
    format!("{n} {unit}{s} ago")
}

fn size(bytes: u64) -> String {
    if bytes >= 1 << 30 {
        format!("{:.1} GiB", bytes as f64 / BYTES_PER_GIB)
    } else {
        format!("{} MiB", (bytes >> 20).max(1))
    }
}

/// Why no snapshot can be taken now (the daemon's limit), if so.
pub fn take_block(snaps: Option<&[Snapshot]>) -> Option<String> {
    let max = stallo::snapshot::MAX_SNAPSHOTS;
    snaps
        .is_some_and(|s| s.len() >= max)
        .then(|| format!("This VM has {max} snapshots, the most it can have. Delete one first."))
}

/// What a new snapshot of `vm` holds.
pub fn take_note(vm: &VmInfo) -> &'static str {
    match kind(&vm.state) {
        Kind::Stopped => "The VM is stopped, so the snapshot holds its disk only.",
        Kind::Running => {
            "The snapshot holds the disk and the memory, so the VM can go back to this very moment. The VM pauses briefly while its memory is saved."
        }
        _ => {
            "The snapshot holds the disk and the memory, so the VM can go back to this very moment."
        }
    }
}

/// The name typed for a new snapshot: none (the daemon picks one), or one
/// that the daemon's own check accepts and that is not taken yet.
pub fn snapshot_name(typed: &str, snaps: Option<&[Snapshot]>) -> Result<Option<String>, String> {
    if typed.is_empty() {
        return Ok(None);
    }
    stallo::config::validate_tag(typed).map_err(|e| printable(&e.to_string(), 200))?;
    if snaps.is_some_and(|s| s.iter().any(|s| s.name == typed)) {
        return Err("A snapshot with this name already exists".to_owned());
    }
    Ok(Some(typed.to_owned()))
}

/// The question before restoring `snap`.
pub fn confirm_restore(vm: &VmInfo, snap: &Snapshot) -> Confirm {
    let (vm_name, tag) = (printable(&vm.name, 64), printable(&snap.name, 64));
    let then = match (snap.ram_bytes > 0, kind(&vm.state)) {
        (true, Kind::Stopped) => "The VM starts from that moment.",
        (true, Kind::Running) => "The VM carries on from that moment.",
        // The daemon resumes only a VM that was running.
        (true, _) => "The VM stays paused at that moment.",
        (false, _) => "The VM stays stopped.",
    };
    Confirm {
        heading: format!("Restore {tag}?"),
        body: format!(
            "{vm_name} goes back to the moment {tag} was taken. Everything that changed since then is lost, unless another snapshot holds it. {then}"
        ),
        button: "Restore",
    }
}

/// The question before deleting snapshot `tag`.
pub fn confirm_delete(vm: &VmInfo, tag: &str) -> Confirm {
    let tag = printable(tag, 64);
    Confirm {
        heading: format!("Delete {tag}?"),
        body: format!(
            "Snapshot {tag} of {} is deleted for good. The VM itself does not change.",
            printable(&vm.name, 64)
        ),
        button: "Delete",
    }
}

const MIB_PER_GIB: f64 = 1024.0;
const BYTES_PER_GIB: f64 = (1u64 << 30) as f64;
/// Addresses shown at most; a guest reports what it likes.
const MAX_ADDRESSES: usize = 16;

/// A VM's overview: groups of (title, value) rows, always the same shape.
pub type Facts = Vec<(&'static str, Vec<(&'static str, String)>)>;

pub fn facts(vm: &VmInfo, details: Option<&VmDetails>) -> Facts {
    let k = kind(&vm.state);
    let memory = if vm.memory_mib.is_multiple_of(1024) {
        format!("{} GiB", vm.memory_mib / 1024)
    } else {
        format!("{} MiB", vm.memory_mib)
    };
    let used = details.map_or("Unknown".to_owned(), |d| {
        format!("{:.1} GiB", d.disk_used_bytes as f64 / BYTES_PER_GIB)
    });
    let net = match vm.net {
        NetProfile::Offline => "Offline",
        NetProfile::Internet => "Internet",
    };
    let forwards = if vm.forwards.is_empty() {
        "None".to_owned()
    } else {
        vm.forwards
            .iter()
            .map(|f| format!("{} → {}", SocketAddr::new(f.bind, f.host), f.guest))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let addresses = match details.map(|d| &d.addresses) {
        _ if k == Kind::Stopped => "None".to_owned(),
        None => "Unknown".to_owned(),
        Some(None) => "The guest agent does not answer".to_owned(),
        Some(Some(a)) if a.is_empty() => "None".to_owned(),
        Some(Some(a)) => a
            .iter()
            .take(MAX_ADDRESSES)
            .map(|(iface, addr)| format!("{}  {}", printable(iface, 32), printable(addr, 64)))
            .collect::<Vec<_>>()
            .join("\n"),
    };
    vec![
        (
            "Resources",
            vec![
                ("State", printable(&vm.state, 64)),
                ("Processors", vm.vcpus.to_string()),
                ("Memory", memory),
                ("Disk Size", format!("{} GiB", vm.disk_gib)),
                ("Disk Used", used),
            ],
        ),
        (
            "Network",
            vec![
                ("Profile", net.to_owned()),
                ("Port Forwards", forwards),
                ("Addresses", addresses),
            ],
        ),
    ]
}

/// The host budget meter in the sidebar.
#[derive(Debug, Clone, PartialEq)]
pub struct Meter {
    /// Memory limits of running VMs as a share of their budget, 0 to 1.
    pub memory_fraction: f64,
    pub memory: String,
    pub disk: String,
    /// Free disk space is below the floor: the watchdog pauses VMs.
    pub disk_low: bool,
}

pub fn meter(h: &HostInfo) -> Meter {
    let fraction = match h.memory_budget_mib {
        0 if h.memory_used_mib > 0 => 1.0,
        0 => 0.0,
        b => (h.memory_used_mib as f64 / b as f64).min(1.0),
    };
    let disk_low = stallo::host::below_floor(h.disk_free_bytes, h.disk_floor_gib);
    let free = h.disk_free_bytes as f64 / BYTES_PER_GIB;
    Meter {
        memory_fraction: fraction,
        memory: format!(
            "VM memory: {:.1} of {:.1} GiB",
            h.memory_used_mib as f64 / MIB_PER_GIB,
            h.memory_budget_mib as f64 / MIB_PER_GIB
        ),
        disk: if disk_low {
            format!(
                "Disk: {free:.1} GiB free, below the {} GiB floor",
                h.disk_floor_gib
            )
        } else {
            format!("Disk: {free:.1} GiB free, floor {} GiB", h.disk_floor_gib)
        },
        disk_low,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe() -> Probe {
        Probe {
            kvm: true,
            explicit: None,
            production: Production::Missing,
            dev: Some("/run/user/1000/stallo-dev/api.sock".into()),
            dev_up: false,
            group: Group {
                listed: true,
                active: true,
            },
            list: None,
        }
    }

    fn state(f: impl FnOnce(&mut Probe)) -> Onboarding {
        let mut p = probe();
        f(&mut p);
        onboarding(&p)
    }

    fn connected() -> Onboarding {
        Onboarding::Connected {
            socket: "/s/api.sock".into(),
        }
    }

    const NOT_LISTED: Group = Group {
        listed: false,
        active: false,
    };
    const NOT_ACTIVE: Group = Group {
        listed: true,
        active: false,
    };

    #[test]
    fn no_kvm_wins() {
        let p = Probe {
            kvm: false,
            list: Some(Ok(1)),
            ..probe()
        };
        assert_eq!(onboarding(&p), Onboarding::NoKvm);
        assert_eq!(socket(&p), None);
    }

    #[test]
    fn daemon_stopped() {
        // No /run/stallo, no dev daemon: nothing to ask (dev socket ENOENT).
        assert_eq!(state(|_| {}), Onboarding::DaemonStopped);
        assert_eq!(
            state(|p| p.list = Some(Err(CallError::NotRunning))),
            Onboarding::DaemonStopped
        );
        // Production socket there, connect refused (stale socket).
        assert_eq!(
            state(|p| {
                p.production = Production::Up;
                p.list = Some(Err(CallError::NotRunning));
            }),
            Onboarding::DaemonStopped
        );
    }

    #[test]
    fn group_states() {
        // /run/stallo closed to us.
        let denied = |g| {
            state(|p| {
                p.production = Production::Denied;
                p.group = g;
            })
        };
        assert_eq!(denied(NOT_LISTED), Onboarding::NotInGroup);
        assert_eq!(denied(NOT_ACTIVE), Onboarding::NeedsRelogin);
        assert!(matches!(denied(probe().group), Onboarding::Unreachable(_)));
        // EACCES on connect itself.
        let eacces = |g| {
            state(|p| {
                p.production = Production::Up;
                p.group = g;
                p.list = Some(Err(CallError::Denied));
            })
        };
        assert_eq!(eacces(NOT_LISTED), Onboarding::NotInGroup);
        assert_eq!(eacces(NOT_ACTIVE), Onboarding::NeedsRelogin);
    }

    #[test]
    fn two_daemons_and_dev_mode() {
        let p = Probe {
            production: Production::Up,
            dev_up: true,
            ..probe()
        };
        assert_eq!(socket(&p), None);
        assert_eq!(
            onboarding(&p),
            Onboarding::TwoDaemons {
                dev: probe().dev.unwrap()
            }
        );
        // STALLO_SOCKET picks one.
        let explicit = Probe {
            explicit: Some("/x/api.sock".into()),
            list: Some(Ok(2)),
            ..p
        };
        assert_eq!(socket(&explicit), Some("/x/api.sock".into()));
        assert_eq!(
            onboarding(&explicit),
            Onboarding::Connected {
                socket: "/x/api.sock".into()
            }
        );
        // A dev daemon while production is closed to us: use dev mode.
        let dev = Probe {
            production: Production::Denied,
            dev_up: true,
            group: NOT_LISTED,
            list: Some(Ok(0)),
            ..probe()
        };
        assert_eq!(socket(&dev), probe().dev);
        assert_eq!(
            onboarding(&dev),
            Onboarding::Connected {
                socket: probe().dev.unwrap()
            }
        );
        // Production only.
        let prod = Probe {
            production: Production::Up,
            ..probe()
        };
        assert_eq!(socket(&prod), Some("/run/stallo/api.sock".into()));
        // Denied and no dev daemon: nothing to ask.
        let denied = Probe {
            production: Production::Denied,
            ..probe()
        };
        assert_eq!(socket(&denied), None);
    }

    #[test]
    fn connected_and_unreachable() {
        assert_eq!(
            state(|p| p.list = Some(Ok(3))),
            Onboarding::Connected {
                socket: probe().dev.unwrap()
            }
        );
        assert!(matches!(
            state(|p| p.list = Some(Err(CallError::Timeout))),
            Onboarding::Unreachable(_)
        ));
        assert_eq!(
            state(|p| p.list = Some(Err(CallError::Failed("boom".into())))),
            Onboarding::Unreachable("boom".into())
        );
    }

    #[test]
    fn etc_group() {
        let etc = "kvm:x:993:\nstallo:x:990:alice,bob\nother:x:5:carol\n";
        assert_eq!(
            group(etc, "bob", &[1000, 990]),
            Group {
                listed: true,
                active: true
            }
        );
        assert_eq!(group(etc, "alice", &[1000]), NOT_ACTIVE);
        assert_eq!(group(etc, "carol", &[5]), NOT_LISTED);
        assert_eq!(group(etc, "ali", &[]), NOT_LISTED);
        assert_eq!(group("stallo:x:990:\n", "bob", &[]), NOT_LISTED);
        assert_eq!(group("", "bob", &[990]), Group::default());
        assert_eq!(group("stallo:x:bad:bob\n", "bob", &[]), Group::default());
    }

    #[test]
    fn scheduler() {
        let onboarding = View {
            page: Onboarding::DaemonStopped,
            reconnecting: false,
        };
        assert!(onboarding.polls(true));
        assert!(!onboarding.polls(false), "hidden");

        let (up, back) = onboarding.next(connected());
        assert!(!back);
        assert!(!up.polls(true), "connected: no polling");

        // Lost: keep the page, show the banner, poll until it is back.
        let (lost, back) = up.next(Onboarding::DaemonStopped);
        assert!(!back);
        assert_eq!(lost.page, connected());
        assert!(lost.reconnecting);
        assert!(lost.polls(true));
        assert!(!lost.polls(false));
        let (lost, _) = lost.next(Onboarding::Unreachable("x".into()));
        assert!(lost.reconnecting);

        let (again, back) = lost.next(connected());
        assert!(back, "toast on recovery");
        assert_eq!(again.page, connected());
        assert!(!again.polls(true));

        // Any other state while connected is shown as a page.
        let (two, back) = again.next(Onboarding::TwoDaemons { dev: "/d".into() });
        assert!(!back);
        assert!(!two.reconnecting);
        assert!(two.polls(true));
    }

    #[test]
    fn explicit_socket_down() {
        let p = Probe {
            explicit: Some("/x/api.sock".into()),
            list: Some(Err(CallError::NotRunning)),
            ..probe()
        };
        let down = Onboarding::SocketDown {
            socket: "/x/api.sock".into(),
        };
        assert_eq!(onboarding(&p), down);
        // Lost while connected: the banner, as for the system service.
        let up = View {
            page: connected(),
            reconnecting: false,
        };
        assert!(up.next(down).0.reconnecting);
    }

    /// The GUI picks the same socket as the CLI, and shows a page that
    /// matches: connected exactly when the CLI's choice gives a socket.
    #[test]
    fn same_choice_as_cli() {
        let prod = PathBuf::from("/run/stallo/api.sock");
        for production in [Production::Up, Production::Missing, Production::Denied] {
            for dev in [None, probe().dev] {
                for dev_up in [false, true] {
                    if dev_up && dev.is_none() {
                        continue; // no path, nothing to find
                    }
                    for group in [NOT_LISTED, NOT_ACTIVE] {
                        let mut p = Probe {
                            production,
                            dev: dev.clone(),
                            dev_up,
                            group,
                            ..probe()
                        };
                        let cli = stallo::paths::pick_socket(
                            (production == Production::Up).then(|| prod.clone()),
                            dev.clone().ok_or_else(|| anyhow::anyhow!("unset")),
                            dev_up,
                            production == Production::Denied,
                        )
                        .ok();
                        assert_eq!(socket(&p), cli, "{p:?}");
                        p.list = cli.as_ref().map(|_| Ok(1));
                        let page = onboarding(&p);
                        assert_eq!(
                            matches!(page, Onboarding::Connected { .. }),
                            cli.is_some(),
                            "{p:?} {page:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn unset_user_is_not_listed() {
        // A trailing comma or an empty list has an empty member.
        for etc in ["stallo:x:990:\n", "stallo:x:990:alice,\n"] {
            assert_eq!(group(etc, "", &[]), NOT_LISTED, "{etc}");
        }
    }

    #[test]
    fn instance_choice() {
        assert!(single_instance(false));
        assert!(!single_instance(true));
    }
    fn vm(state: &str) -> VmInfo {
        VmInfo {
            name: "dev".into(),
            state: state.into(),
            vcpus: 2,
            memory_mib: 2048,
            disk_gib: 20,
            net: NetProfile::Offline,
            forwards: vec![],
            agent_control: false,
            vnc: false,
        }
    }

    #[test]
    fn kinds() {
        for (state, k) in [
            ("stopped", Kind::Stopped),
            ("running", Kind::Running),
            ("running (no network)", Kind::Running),
            ("paused", Kind::Paused),
            ("paused (no network)", Kind::Paused),
            ("save-vm", Kind::Paused),
            ("paused (disk full)", Kind::DiskFull),
            ("io-error", Kind::Failed),
            ("guest-panicked", Kind::Failed),
            ("unknown", Kind::Failed),
            ("", Kind::Paused),
        ] {
            assert_eq!(kind(state), k, "{state}");
        }
    }

    #[test]
    fn rows() {
        let r = row(&vm("running"));
        assert_eq!(r.name, "dev");
        assert_eq!(r.tone, Some("success"));
        assert_eq!(r.control_icon, "avatar-default-symbolic");
        assert_eq!(r.control_tip, "Agent control off");
        let on = VmInfo {
            agent_control: true,
            ..vm("stopped")
        };
        let r = row(&on);
        assert_eq!(r.tone, None);
        assert_eq!(r.control_icon, "security-high-symbolic");
        assert_eq!(row(&vm("paused (disk full)")).tone, Some("warning"));
        assert_eq!(row(&vm("io-error")).tone, Some("error"));
        // Daemon text is cleaned and capped before it reaches a label.
        let odd = VmInfo {
            name: "a\u{202E}b\n".into(),
            ..vm(&"x".repeat(500))
        };
        let r = row(&odd);
        assert_eq!(r.name, "ab");
        assert_eq!(r.state.len(), 64);
    }

    #[test]
    fn action_matrix() {
        const STOPPED: ActionSet = ActionSet {
            start: true,
            stop: false,
            force_off: false,
            reset: false,
            resume: false,
            halted: false,
        };
        const RUNNING: ActionSet = ActionSet {
            start: false,
            stop: true,
            force_off: true,
            reset: true,
            resume: false,
            halted: false,
        };
        // No plain Stop: the daemon would quit QEMU without a shutdown.
        const HALTED: ActionSet = ActionSet {
            start: false,
            stop: false,
            force_off: true,
            reset: false,
            resume: true,
            halted: true,
        };
        for (state, want) in [
            ("stopped", STOPPED),
            ("running", RUNNING),
            ("running (no network)", RUNNING),
            ("paused", HALTED),
            ("paused (no network)", HALTED),
            ("paused (disk full)", HALTED),
            ("io-error", HALTED),
            ("unknown", HALTED),
        ] {
            assert_eq!(actions(&vm(state), false), want, "{state}");
            // Blocked: nothing, but the layout stays.
            let busy = actions(&vm(state), true);
            assert!(Op::ALL.iter().all(|&op| !busy.allows(op)), "{state}");
            assert_eq!(busy.halted, want.halted, "{state}");
            for op in Op::ALL {
                let field = match op {
                    Op::Start => want.start,
                    Op::Stop => want.stop,
                    Op::ForceOff => want.force_off,
                    Op::Reset => want.reset,
                    Op::Resume => want.resume,
                };
                assert_eq!(want.allows(op), field);
            }
        }
    }

    #[test]
    fn ops() {
        let wire = |op: Op| serde_json::to_string(&op.request("dev")).unwrap();
        assert_eq!(
            wire(Op::Start),
            r#"{"op":"start","name":"dev","wait":false}"#
        );
        assert_eq!(
            wire(Op::Stop),
            r#"{"op":"stop","name":"dev","force":false}"#
        );
        assert_eq!(
            wire(Op::ForceOff),
            r#"{"op":"stop","name":"dev","force":true}"#
        );
        assert_eq!(wire(Op::Reset), r#"{"op":"reset","name":"dev"}"#);
        assert_eq!(wire(Op::Resume), r#"{"op":"resume","name":"dev"}"#);
        for op in Op::ALL {
            assert_eq!(op.limit(), Duration::from_secs(150));
        }
        assert_eq!(
            Op::ForceOff.failed("dev", &CallError::Failed("no\u{1b}[31m way".into())),
            "Could not force off dev: no[31m way"
        );
        assert_eq!(
            Op::Start.failed("dev", &CallError::Timeout),
            "Could not start dev: no answer in time"
        );
    }

    #[test]
    fn confirmations() {
        let running = vm("running");
        let c = confirm(Op::ForceOff, &running).unwrap();
        assert_eq!(c.heading, "Force Off dev?");
        assert_eq!(
            c.body,
            "Unsaved work in the VM is lost and its file systems may need repair."
        );
        assert_eq!(c.button, "Force Off");
        let c = confirm(Op::Reset, &running).unwrap();
        assert_eq!((c.heading.as_str(), c.button), ("Reset dev?", "Reset"));
        let paused = confirm(Op::ForceOff, &vm("paused (disk full)")).unwrap();
        assert!(
            paused
                .body
                .starts_with("The VM does not run, so it cannot shut down cleanly.")
        );
        for op in [Op::Start, Op::Stop, Op::Resume] {
            assert_eq!(confirm(op, &running), None);
        }
        let odd = VmInfo {
            name: "a\u{202E}b".into(),
            ..running
        };
        assert_eq!(confirm(Op::Reset, &odd).unwrap().heading, "Reset ab?");
    }

    #[test]
    fn pending_until_a_fresh_list() {
        let t0 = Instant::now();
        let s = Duration::from_secs(1);
        let mut p = Pending::default();
        assert!(!p.blocks("dev"));
        assert!(p.start("dev"));
        assert!(!p.start("dev"), "one action per VM");
        assert!(p.start("web"));
        p.listed(t0 + s);
        assert!(p.blocks("dev"), "still running");
        p.finish("dev", t0 + 2 * s);
        p.listed(t0 + s);
        assert!(p.blocks("dev"), "that list was asked for before the end");
        p.listed(t0 + 2 * s);
        assert!(!p.blocks("dev"));
        assert!(p.blocks("web"));
        assert!(p.start("dev"));
    }

    #[test]
    fn polls() {
        let t0 = Instant::now();
        let mut p = Poll::new(LIST_EVERY);
        assert!(p.due(t0), "first tick asks at once");
        assert!(!p.due(t0 + BACKOFF), "never two at once");
        p.done(t0, true);
        assert!(!p.due(t0 + LIST_EVERY - Duration::from_millis(1)));
        assert!(p.due(t0 + LIST_EVERY));
        p.done(t0, false);
        assert!(!p.due(t0 + LIST_EVERY), "backs off after an error");
        assert!(p.due(t0 + BACKOFF));
        p.done(t0, true);
        p.soon();
        assert!(p.due(t0), "soon: at the next tick");
        // Asked for while a request is out: once more right after it.
        p.soon();
        assert!(!p.due(t0), "still one at a time");
        p.done(t0, true);
        assert!(p.due(t0), "the answer may predate the change");
        p.done(t0, true);
        assert!(!p.due(t0), "and then the normal pace");
        p.soon();
        p.soon();
        assert!(p.due(t0));
        p.soon();
        p.done(t0, false);
        assert!(!p.due(t0 + LIST_EVERY), "errors still back off");
        let mut host = Poll::new(HOST_EVERY);
        assert!(host.due(t0));
        host.done(t0, true);
        assert!(!host.due(t0 + LIST_EVERY));
        assert!(host.due(t0 + HOST_EVERY));

        // List and host polling: only while visible and connected.
        let view = View {
            page: connected(),
            reconnecting: false,
        };
        assert!(view.polls_vms(true));
        assert!(!view.polls_vms(false));
        let lost = View {
            reconnecting: true,
            ..view.clone()
        };
        assert!(!lost.polls_vms(true), "the probe takes over");
        let page = View {
            page: Onboarding::DaemonStopped,
            reconnecting: false,
        };
        assert!(!page.polls_vms(true));

        // Details: while visible and running, once when stopped.
        assert!(wants_info(true, Kind::Running, true));
        assert!(!wants_info(false, Kind::Running, false));
        assert!(wants_info(true, Kind::Stopped, false));
        assert!(!wants_info(true, Kind::Stopped, true));
        assert!(!wants_info(true, Kind::Paused, true));
    }

    #[test]
    fn overview() {
        let values = |f: Facts| -> Vec<String> {
            f.into_iter()
                .flat_map(|(_, rows)| rows.into_iter().map(|(_, v)| v))
                .collect()
        };
        let titles = |f: &Facts| -> Vec<&str> {
            f.iter()
                .flat_map(|(_, rows)| rows.iter().map(|(t, _)| *t))
                .collect()
        };
        let stopped = facts(&vm("stopped"), None);
        let shape = titles(&stopped);
        assert_eq!(
            values(stopped),
            [
                "stopped", "2", "2 GiB", "20 GiB", "Unknown", "Offline", "None", "None"
            ]
        );

        let web = VmInfo {
            memory_mib: 1536,
            net: NetProfile::Internet,
            forwards: vec![
                stallo::config::PortForward {
                    bind: "127.0.0.1".parse().unwrap(),
                    host: 8080,
                    guest: 80,
                },
                stallo::config::PortForward {
                    bind: "::1".parse().unwrap(),
                    host: 2222,
                    guest: 22,
                },
            ],
            ..vm("running")
        };
        let details = |addresses| VmDetails {
            vm: web.clone(),
            addresses,
            disk_used_bytes: 3 << 29,
            vnc_socket: None,
        };
        let f = facts(
            &web,
            Some(&details(Some(vec![
                ("eth0".into(), "10.0.2.15/24".into()),
                ("e\u{202E}vil\n".into(), "fe80::1/64\u{1b}".into()),
            ]))),
        );
        assert_eq!(titles(&f), shape, "same rows every time");
        assert_eq!(
            values(f),
            [
                "running",
                "2",
                "1536 MiB",
                "20 GiB",
                "1.5 GiB",
                "Internet",
                "127.0.0.1:8080 → 80\n[::1]:2222 → 22",
                "eth0  10.0.2.15/24\nevil  fe80::1/64",
            ]
        );
        let addresses =
            |d: Option<VmDetails>, state| values(facts(&vm(state), d.as_ref()))[7].clone();
        assert_eq!(addresses(None, "running"), "Unknown");
        assert_eq!(
            addresses(Some(details(None)), "running"),
            "The guest agent does not answer"
        );
        assert_eq!(addresses(Some(details(Some(vec![]))), "running"), "None");
        // Old addresses of a VM that stopped since are not shown.
        let old = Some(vec![("eth0".into(), "10.0.2.15/24".into())]);
        assert_eq!(addresses(Some(details(old)), "stopped"), "None");
        // A guest cannot flood the page.
        let many = (0..100)
            .map(|i| ("eth0".into(), format!("10.0.0.{i}/8")))
            .collect();
        assert_eq!(
            addresses(Some(details(Some(many))), "running")
                .lines()
                .count(),
            MAX_ADDRESSES
        );
    }

    #[test]
    fn host_meter() {
        let host = HostInfo {
            cores: 8,
            vcpus_allotted: 2,
            memory_total_mib: 32768,
            memory_available_mib: 20000,
            memory_budget_mib: 24576,
            memory_used_mib: 6144,
            disk_free_bytes: 100 << 30,
            disk_floor_gib: 20,
            running_vms: 1,
        };
        let m = meter(&host);
        assert_eq!(m.memory_fraction, 0.25);
        assert_eq!(m.memory, "VM memory: 6.0 of 24.0 GiB");
        assert_eq!(m.disk, "Disk: 100.0 GiB free, floor 20 GiB");
        assert!(!m.disk_low);
        let low = meter(&HostInfo {
            disk_free_bytes: 10 << 30,
            memory_used_mib: 30000,
            ..host.clone()
        });
        assert!(low.disk_low);
        assert_eq!(low.disk, "Disk: 10.0 GiB free, below the 20 GiB floor");
        assert_eq!(low.memory_fraction, 1.0, "capped");
        let no_budget = |used| {
            meter(&HostInfo {
                memory_budget_mib: 0,
                memory_used_mib: used,
                ..host.clone()
            })
            .memory_fraction
        };
        assert_eq!(no_budget(0), 0.0);
        assert_eq!(no_budget(1), 1.0);
    }

    fn snap(name: &str, ram_bytes: u64, created: u64, vm_clock_ms: u64) -> Snapshot {
        Snapshot {
            name: name.into(),
            ram_bytes,
            created,
            vm_clock_ms,
        }
    }

    #[test]
    fn snapshot_timeline() {
        let snaps = [
            snap("disk", 0, 1000, 0),
            snap("before-upgrade", 412 << 20, 9_000, 754_000),
            snap("big", 3 << 29, 9_990, 1),
            snap("lost", 0, 9_999, 5_000),
        ];
        let rows = timeline(&vm("stopped"), &snaps, 10_000);
        let names: Vec<&str> = rows.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(
            names,
            ["lost", "big", "before-upgrade", "disk"],
            "newest first"
        );
        let subtitles: Vec<&str> = rows.iter().map(|r| r.subtitle.as_str()).collect();
        assert_eq!(
            subtitles,
            [
                "Just now",
                "Just now · 1.5 GiB",
                "16 minutes ago · 412 MiB",
                "2 hours ago"
            ]
        );
        assert_eq!(
            rows.iter().map(|r| r.memory).collect::<Vec<_>>(),
            [false, true, true, false]
        );
        // Stopped: everything restores but a RAM snapshot whose RAM is gone.
        let blocks: Vec<_> = rows.iter().map(|r| r.restore_block).collect();
        assert!(blocks[0].unwrap().contains("missing"));
        assert_eq!(&blocks[1..], [None, None, None]);
        // Running: a disk-only snapshot needs the VM stopped first.
        for state in ["running", "paused", "paused (disk full)"] {
            let rows = timeline(&vm(state), &snaps, 10_000);
            assert!(
                rows[0].restore_block.unwrap().contains("missing"),
                "{state}"
            );
            assert_eq!(rows[1].restore_block, None, "{state}");
            assert!(
                rows[3].restore_block.unwrap().starts_with("Stop the VM"),
                "{state}"
            );
        }
        // Clock skew: never "in the future".
        assert_eq!(
            timeline(&vm("stopped"), &snaps[..1], 0)[0].subtitle,
            "Just now"
        );
        // Daemon text is cleaned; the raw name goes back to the daemon.
        let odd = timeline(&vm("stopped"), &[snap("a\u{202E}b", 0, 0, 0)], 0);
        assert_eq!(
            (odd[0].name.as_str(), odd[0].tag.as_str()),
            ("ab", "a\u{202E}b")
        );
        for (secs, text) in [
            (59, "Just now"),
            (60, "1 minute ago"),
            (7199, "1 hour ago"),
            (7200, "2 hours ago"),
            (86_400, "1 day ago"),
            (10 * 86_400, "10 days ago"),
        ] {
            assert_eq!(age(secs), text);
        }
        assert_eq!(size(1), "1 MiB");
    }

    #[test]
    fn taking_snapshots() {
        let max = stallo::snapshot::MAX_SNAPSHOTS;
        let full: Vec<Snapshot> = (0..max).map(|i| snap(&format!("s{i}"), 0, 0, 0)).collect();
        assert_eq!(take_block(None), None);
        assert_eq!(take_block(Some(&full[1..])), None);
        assert!(take_block(Some(&full)).unwrap().contains(&max.to_string()));
        assert!(take_note(&vm("running")).contains("pauses briefly"));
        assert!(take_note(&vm("stopped")).contains("disk only"));
        assert!(!take_note(&vm("paused")).contains("pauses"));

        let some = Some(&full[..2]);
        assert_eq!(snapshot_name("", some), Ok(None));
        assert_eq!(
            snapshot_name("before-upgrade.2", some),
            Ok(Some("before-upgrade.2".into()))
        );
        assert_eq!(
            snapshot_name("s1", some),
            Err("A snapshot with this name already exists".into())
        );
        assert_eq!(snapshot_name("s1", None), Ok(Some("s1".into())));
        // The library's own check, passed through.
        for bad in ["1st", "with space", "a/b", "-x", &"x".repeat(65), "é"] {
            let e = snapshot_name(bad, some).unwrap_err();
            assert!(e.starts_with("invalid snapshot name"), "{bad}: {e}");
            assert!(stallo::config::validate_tag(bad).is_err());
        }
        assert!(
            !snapshot_name("a\u{1b}[31m", None)
                .unwrap_err()
                .contains('\u{1b}')
        );
    }

    #[test]
    fn snapshot_list_waits_after_a_timeout() {
        let t0 = Instant::now();
        let stuck = ("running".to_owned(), t0);
        assert!(!snaps_wait(None, "running", t0));
        assert!(snaps_wait(Some(&stuck), "running", t0 + BACKOFF));
        assert!(!snaps_wait(Some(&stuck), "stopped", t0), "state changed");
        assert!(!snaps_wait(Some(&stuck), "running", t0 + SNAP_LIMIT));
    }

    #[test]
    fn snapshot_confirmations() {
        let ram = snap("s1", 1 << 20, 0, 1);
        let disk = snap("s2", 0, 0, 0);
        let c = confirm_restore(&vm("running"), &ram);
        assert_eq!((c.heading.as_str(), c.button), ("Restore s1?", "Restore"));
        assert_eq!(
            c.body,
            "dev goes back to the moment s1 was taken. Everything that changed since then is lost, unless another snapshot holds it. The VM carries on from that moment."
        );
        assert!(
            confirm_restore(&vm("stopped"), &ram)
                .body
                .ends_with("The VM starts from that moment.")
        );
        assert!(
            confirm_restore(&vm("stopped"), &disk)
                .body
                .ends_with("The VM stays stopped.")
        );
        for state in ["paused", "paused (disk full)", "io-error"] {
            assert!(
                confirm_restore(&vm(state), &ram)
                    .body
                    .ends_with("The VM stays paused at that moment."),
                "{state}"
            );
        }
        let c = confirm_delete(&vm("running"), "s\u{202E}1");
        assert_eq!((c.heading.as_str(), c.button), ("Delete s1?", "Delete"));
        assert_eq!(
            c.body,
            "Snapshot s1 of dev is deleted for good. The VM itself does not change."
        );
    }

    #[test]
    fn snapshot_actions() {
        let wire = |a: Action| serde_json::to_string(&a.request("dev")).unwrap();
        assert_eq!(
            wire(Action::Take(None)),
            r#"{"op":"snapshot","name":"dev","tag":null}"#
        );
        assert_eq!(
            wire(Action::Take(Some("s1".into()))),
            r#"{"op":"snapshot","name":"dev","tag":"s1"}"#
        );
        assert_eq!(
            wire(Action::Restore("s1".into())),
            r#"{"op":"restore","name":"dev","tag":"s1"}"#
        );
        assert_eq!(
            wire(Action::Delete("s1".into())),
            r#"{"op":"snapshot_delete","name":"dev","tag":"s1"}"#
        );
        assert_eq!(
            wire(Action::Life(Op::Reset)),
            r#"{"op":"reset","name":"dev"}"#
        );
        assert_eq!(Action::Take(None).limit(), Duration::from_secs(900));
        assert_eq!(Action::Delete("s".into()).limit(), SNAP_LIMIT);
        assert_eq!(Action::Life(Op::Stop).limit(), Op::Stop.limit());
        assert!(
            Op::ALL.iter().all(|op| op.limit() <= SNAP_LIMIT),
            "the longest"
        );

        let e = CallError::Timeout;
        assert_eq!(
            Action::Take(None).failed("dev", &e),
            "The snapshot of dev takes long and may still be running; check the list later"
        );
        assert_eq!(
            Action::Restore("s1".into()).failed("dev", &e),
            "Restoring s1 takes long and may still be running; check the list later"
        );
        assert_eq!(
            Action::Delete("s\u{1b}1".into()).failed("dev", &CallError::Denied),
            "Could not delete s1: permission denied"
        );
        assert_eq!(
            Action::Life(Op::Start).failed("dev", &e),
            Op::Start.failed("dev", &e)
        );
        let taken = serde_json::json!({"name": "snap3\u{1b}", "ram": true, "ms": 5});
        assert_eq!(
            Action::Take(None).done("dev", &taken).as_deref(),
            Some("Snapshot snap3 taken")
        );
        assert_eq!(
            Action::Take(None)
                .done("dev", &serde_json::Value::Null)
                .as_deref(),
            Some("Snapshot taken")
        );
        assert_eq!(
            Action::Restore("s1".into())
                .done("dev", &serde_json::Value::Null)
                .as_deref(),
            Some("dev restored to s1")
        );
        assert_eq!(
            Action::Delete("s1".into())
                .done("dev", &serde_json::Value::Null)
                .as_deref(),
            Some("Snapshot s1 deleted")
        );
        assert_eq!(
            Action::Life(Op::Start).done("dev", &serde_json::Value::Null),
            None
        );
    }

    #[test]
    fn call_errors_read_plainly() {
        assert_eq!(CallError::NotRunning.to_string(), "Stallo is not running");
        assert_eq!(CallError::Denied.to_string(), "permission denied");
        assert_eq!(
            CallError::Failed("a\u{202E}b".repeat(200))
                .to_string()
                .len(),
            300
        );
    }
}
