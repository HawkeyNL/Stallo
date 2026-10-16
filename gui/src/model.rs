//! Plain-Rust view-model: what the window should show, decided from facts
//! gathered elsewhere (no GTK, no I/O), so every case is unit-testable.

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use stallo::api::{Request, VmDetails, VmInfo};
use stallo::config::NetProfile;
use stallo::host::HostInfo;
use stallo::printable;
use stallo::snapshot::Snapshot;

use crate::rfb::Input;

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

/// A VM's state in plain words. Other QEMU states get the word for their
/// [`Kind`]; the daemon's own word goes in the tooltip.
pub fn state_word(state: &str) -> &'static str {
    match state.strip_suffix(" (no network)").unwrap_or(state) {
        "stopped" => "Stopped",
        "running" => "Running",
        "paused" => "Paused",
        "paused (disk full)" => "Disk Full",
        "io-error" | "internal-error" => "Error",
        "guest-panicked" => "Crashed",
        "unknown" => "Not Responding",
        // On the way somewhere.
        "save-vm" => "Saving",
        "restore-vm" | "inmigrate" => "Restoring",
        "prelaunch" => "Starting",
        "shutdown" => "Shutting Down",
        "suspended" => "Suspended",
        _ => match kind(state) {
            Kind::Stopped => "Stopped",
            Kind::Running => "Running",
            Kind::Paused => "Paused",
            Kind::DiskFull => "Disk Full",
            Kind::Failed => "Error",
        },
    }
}

/// A VM in the sidebar. Strings are safe to show in plain labels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowVm {
    pub name: String,
    /// The state in plain words.
    pub state: &'static str,
    /// The daemon's own word for the state, for the tooltip.
    pub raw: String,
    /// The libadwaita style class for the state, if any.
    pub tone: Option<&'static str>,
    /// An agent may control the VM.
    pub agent: bool,
    /// The action that runs on the VM now, in words.
    pub working: Option<&'static str>,
}

impl RowVm {
    /// What a screen reader says for the row.
    pub fn label(&self) -> String {
        let mut label = format!("{}, {}", self.name, self.state);
        if self.agent {
            label.push_str(", agent control on");
        }
        if let Some(w) = self.working {
            label.push_str(", ");
            label.push_str(w);
        }
        label
    }
}

pub fn row(vm: &VmInfo, working: Option<&Action>) -> RowVm {
    let tone = match kind(&vm.state) {
        Kind::Stopped => None,
        Kind::Running => Some("success"),
        Kind::Paused | Kind::DiskFull => Some("warning"),
        Kind::Failed => Some("error"),
    };
    RowVm {
        name: printable(&vm.name, 64),
        state: state_word(&vm.state),
        raw: printable(&vm.state, 64),
        tone,
        agent: vm.agent_control,
        working: working.map(Action::progress),
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
}

/// An error for a toast: a short title, and the whole error with a next
/// step behind its Details button. Safe for plain labels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub title: String,
    pub details: Option<String>,
}

/// A request that failed; `title` says what did not happen.
pub fn failure(title: String, e: &CallError) -> Failure {
    let text = match e {
        CallError::Failed(m) => printable(m, 2000),
        _ => e.to_string(),
    };
    let details = match next_step(e) {
        Some(step) => format!("{text}\n\n{step}"),
        None => text,
    };
    Failure {
        title,
        details: Some(details),
    }
}

/// What to do about errors whose cause is known.
// ponytail: matches the daemon's English text; give errors a code in the
// API if more of them need a next step.
fn next_step(e: &CallError) -> Option<&'static str> {
    let msg = match e {
        CallError::NotRunning => return Some("Start the Stallo service, then try again."),
        CallError::Denied => return Some("Check that your account is in the stallo group."),
        CallError::Timeout => {
            return Some("Stallo may still be working on it. Look at the VM again in a moment.");
        }
        CallError::Failed(m) => m,
    };
    if msg.contains("guest agent") {
        Some("Check that qemu-guest-agent is installed and running in the VM.")
    } else if msg.contains("GiB floor") {
        Some("Free up disk space on the host, then try again.")
    } else if msg == "stallod is busy; try again" {
        // The daemon itself has too many requests.
        Some("Stallo is busy. Try again in a moment.")
    } else if msg.contains(" is busy;")
        || msg.contains(" is busy with")
        || msg.contains("in use by `stallo run`")
    {
        Some("Something else is using this VM. Wait until it is done, then try again.")
    } else {
        None
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
    /// Turns the live screen (VNC) on or off from the next start.
    LiveScreen(bool),
    /// Stops the VM cleanly and starts it again, after turning the live
    /// screen on if `live_screen`.
    Restart {
        live_screen: bool,
    },
}

impl Action {
    /// The requests to send, in order; the first error ends the action.
    pub fn requests(&self, vm: &str) -> Vec<Request> {
        let name = vm.to_owned();
        let live_screen = |on| Request::SetVnc {
            name: vm.to_owned(),
            on,
        };
        match self {
            Action::Life(op) => vec![op.request(vm)],
            Action::Take(tag) => vec![Request::Snapshot {
                name,
                tag: tag.clone(),
            }],
            Action::Restore(tag) => vec![Request::Restore {
                name,
                tag: Some(tag.clone()),
            }],
            Action::Delete(tag) => vec![Request::SnapshotDelete {
                name,
                tag: tag.clone(),
            }],
            Action::LiveScreen(on) => vec![live_screen(*on)],
            Action::Restart { live_screen: on } => on
                .then(|| live_screen(true))
                .into_iter()
                .chain([Op::Stop.request(vm), Op::Start.request(vm)])
                .collect(),
        }
    }

    /// The time limit of each request.
    pub fn limit(&self) -> Duration {
        match self {
            Action::Take(_) | Action::Restore(_) | Action::Delete(_) => SNAP_LIMIT,
            _ => Op::Stop.limit(),
        }
    }

    /// Whether it waits for the lifecycle slots, not the snapshot ones.
    pub fn lifecycle(&self) -> bool {
        matches!(
            self,
            Action::Life(_) | Action::LiveScreen(_) | Action::Restart { .. }
        )
    }

    /// What is left of it from request `step` on, the one that failed:
    /// what the error toast is about.
    pub fn failed_at(&self, step: usize) -> Action {
        match self {
            // The live screen is on; only the restart failed.
            Action::Restart { live_screen: true } if step > 0 => {
                Action::Restart { live_screen: false }
            }
            a => a.clone(),
        }
    }

    /// The toast when it fails. A snapshot action that timed out may
    /// still run in the daemon.
    pub fn failed(&self, vm: &str, e: &CallError) -> Failure {
        let vm = printable(vm, 64);
        let (what, slow) = match self {
            Action::Life(op) => {
                let verb = match op {
                    Op::Start => "start",
                    Op::Stop => "stop",
                    Op::ForceOff => "force off",
                    Op::Reset => "reset",
                    Op::Resume => "resume",
                };
                (format!("{verb} {vm}"), None)
            }
            Action::LiveScreen(on) => (
                format!(
                    "turn {} the live screen of {vm}",
                    if *on { "on" } else { "off" }
                ),
                None,
            ),
            Action::Restart { live_screen: true } => {
                (format!("turn on the live screen and restart {vm}"), None)
            }
            Action::Restart { live_screen: false } => (format!("restart {vm}"), None),
            Action::Take(_) => (
                format!("take a snapshot of {vm}"),
                Some(format!("Snapshot of {vm} still running")),
            ),
            Action::Restore(tag) => {
                let tag = printable(tag, 64);
                (
                    format!("restore {tag}"),
                    Some(format!("Restore of {tag} still running")),
                )
            }
            Action::Delete(tag) => {
                let tag = printable(tag, 64);
                (
                    format!("delete {tag}"),
                    Some(format!("Deletion of {tag} still running")),
                )
            }
        };
        match (e, slow) {
            (CallError::Timeout, Some(slow)) => Failure {
                title: slow,
                details: Some(
                    "Stallo stopped waiting for an answer, but the job may still finish. Check the snapshot list later."
                        .to_owned(),
                ),
            },
            _ => failure(format!("Could not {what}"), e),
        }
    }

    /// What the window says while it runs.
    pub fn progress(&self) -> &'static str {
        match self {
            Action::Life(Op::Start) => "Starting…",
            Action::Life(Op::Stop) => "Stopping…",
            Action::Life(Op::ForceOff) => "Forcing off…",
            Action::Life(Op::Reset) => "Resetting…",
            Action::Life(Op::Resume) => "Resuming…",
            Action::Take(_) => "Taking snapshot…",
            Action::Restore(_) => "Restoring snapshot…",
            Action::Delete(_) => "Deleting snapshot…",
            Action::LiveScreen(true) => "Turning on live screen…",
            Action::LiveScreen(false) => "Turning off live screen…",
            Action::Restart { .. } => "Restarting…",
        }
    }

    /// The toast when it worked, given the daemon's answer. Snapshot
    /// actions may take minutes, so they say when they are done.
    pub fn done(&self, vm: &str, data: &serde_json::Value) -> Option<String> {
        let vm = printable(vm, 64);
        match self {
            // The Screen tab shows the outcome.
            Action::Life(_) | Action::LiveScreen(_) | Action::Restart { .. } => None,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActionSet {
    pub start: bool,
    pub stop: bool,
    pub force_off: bool,
    pub reset: bool,
    pub resume: bool,
    /// The one header button for the state: Start, the Stop split button
    /// (Force Off, Reset), or the Resume split button (Force Off) for a VM
    /// that exists but does not run (paused, disk full, io-error...).
    pub primary: Op,
    /// The primary button is the obvious next step (`suggested-action`):
    /// not Resume of a VM that failed.
    pub suggested: bool,
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
/// just ran, or the daemon is out of reach. The header keeps its layout.
pub fn actions(vm: &VmInfo, blocked: bool) -> ActionSet {
    let k = kind(&vm.state);
    let primary = match k {
        Kind::Stopped => Op::Start,
        Kind::Running => Op::Stop,
        // The daemon stops a VM that does not run with a hard QMP quit,
        // so it gets no plain Stop.
        _ => Op::Resume,
    };
    let on = !blocked;
    ActionSet {
        start: on && primary == Op::Start,
        stop: on && primary == Op::Stop,
        force_off: on && primary != Op::Start,
        reset: on && primary == Op::Stop,
        resume: on && primary == Op::Resume,
        primary,
        suggested: primary == Op::Start || (primary == Op::Resume && k != Kind::Failed),
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
pub struct Pending(HashMap<String, (Action, Option<Instant>)>);

impl Pending {
    /// Claims `vm` for `action`; false if it has one already.
    pub fn start(&mut self, vm: &str, action: &Action) -> bool {
        if self.0.contains_key(vm) {
            return false;
        }
        self.0.insert(vm.to_owned(), (action.clone(), None));
        true
    }

    pub fn finish(&mut self, vm: &str, now: Instant) {
        if let Some((_, end)) = self.0.get_mut(vm) {
            *end = Some(now);
        }
    }

    /// A VM list arrived that was asked for at `sent`.
    pub fn listed(&mut self, sent: Instant) {
        self.0
            .retain(|_, (_, end)| end.is_none_or(|end| end > sent));
    }

    pub fn blocks(&self, vm: &str) -> bool {
        self.0.contains_key(vm)
    }

    /// The action that holds `vm`, if any.
    pub fn action(&self, vm: &str) -> Option<&Action> {
        self.0.get(vm).map(|(a, _)| a)
    }
}

/// Whether to ask for an open VM's details: while its page is visible and
/// it runs, and once for a stopped VM (disk use). `have`: details from
/// the VM's current kind of state.
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
    /// When it was taken and what it holds, and why it cannot be restored
    /// now, if so.
    pub subtitle: String,
    /// Why it cannot be restored now, whatever else runs.
    pub restore_block: Option<&'static str>,
    /// An action on this snapshot runs now, in words.
    pub working: Option<&'static str>,
}

/// The timeline: newest first. `now` is the host clock in Unix seconds;
/// `running` is the action that holds the VM, if any.
pub fn timeline(
    vm: &VmInfo,
    snaps: &[Snapshot],
    now: u64,
    running: Option<&Action>,
) -> Vec<SnapRow> {
    snaps
        .iter()
        .rev()
        .map(|s| {
            let mut subtitle = age(now.saturating_sub(s.created));
            if s.ram_bytes > 0 {
                subtitle.push_str(&format!(" · Disk and memory ({})", size(s.ram_bytes)));
            } else {
                subtitle.push_str(" · Disk only");
            }
            let restore_block = restore_block(vm, s);
            if let Some(why) = restore_block {
                subtitle.push('\n');
                subtitle.push_str(why);
            }
            let working = match running {
                Some(Action::Restore(t)) if *t == s.name => Some("Restoring…"),
                Some(Action::Delete(t)) if *t == s.name => Some("Deleting…"),
                _ => None,
            };
            SnapRow {
                tag: s.name.clone(),
                name: printable(&s.name, 64),
                subtitle,
                restore_block,
                working,
            }
        })
        .collect()
}

/// The daemon's restore rules, so the button is off where it would refuse.
fn restore_block(vm: &VmInfo, snap: &Snapshot) -> Option<&'static str> {
    if stallo::snapshot::ram_missing(snap) {
        Some("Its saved memory is missing, so it cannot be restored.")
    } else if snap.ram_bytes == 0 && kind(&vm.state) != Kind::Stopped {
        Some("Stop the VM to restore this snapshot.")
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
/// The prefilled suggestion counts as none: the daemon picks a free name
/// itself, and may know names the list does not show.
pub fn snapshot_name(typed: &str, snaps: Option<&[Snapshot]>) -> Result<Option<String>, String> {
    if typed.is_empty() || typed == suggested_name(snaps) {
        return Ok(None);
    }
    if stallo::config::validate_tag(typed).is_err() {
        return Err(
            "Use up to 64 letters, digits, '.', '_' or '-', starting with a letter.".to_owned(),
        );
    }
    if snaps.is_some_and(|s| s.iter().any(|s| s.name == typed)) {
        return Err("A snapshot with this name already exists".to_owned());
    }
    Ok(Some(typed.to_owned()))
}

/// The name a new snapshot gets unless the user types another: the next
/// free `snapN`, or none while the list is not known yet.
pub fn suggested_name(snaps: Option<&[Snapshot]>) -> String {
    snaps.map_or_else(String::new, |s| {
        let names: Vec<String> = s.iter().map(|s| s.name.clone()).collect();
        stallo::snapshot::next_name(&names)
    })
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
        NetProfile::Offline => "Off",
        // The daemon cut it: the network check failed.
        NetProfile::Internet if vm.state.ends_with(" (no network)") => {
            "Cut off until the VM restarts"
        }
        NetProfile::Internet => "On",
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
        Some(None) => "Unknown (install qemu-guest-agent in the VM to see addresses)".to_owned(),
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
                ("State", state_word(&vm.state).to_owned()),
                ("Processors", vm.vcpus.to_string()),
                ("Memory", memory),
                ("Disk Size", format!("{} GiB", vm.disk_gib)),
                ("Disk Used", used),
            ],
        ),
        (
            "Network",
            vec![
                ("Internet Access", net.to_owned()),
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
    // Rounded down: never "20 GiB free" while below a 20 GiB limit.
    let free = (h.disk_free_bytes as f64 / BYTES_PER_GIB).floor();
    // Whole GiB where it is one, else one decimal.
    let gib = |mib: u64| {
        let g = mib as f64 / MIB_PER_GIB;
        if mib.is_multiple_of(1024) {
            format!("{g:.0}")
        } else {
            format!("{g:.1}")
        }
    };
    Meter {
        memory_fraction: fraction,
        memory: format!(
            "VM memory: {} of {} GiB",
            gib(h.memory_used_mib),
            gib(h.memory_budget_mib)
        ),
        disk: if disk_low {
            format!(
                "Disk: {free:.0} GiB free. VMs pause below {} GiB.",
                h.disk_floor_gib
            )
        } else {
            format!("Disk: {free:.0} GiB free")
        },
        disk_low,
    }
}

/// What the Screen tab shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScreenPage {
    /// The VM does not run; its live screen is on.
    Stopped,
    /// No live screen. `on`: it is on, and comes with the next start.
    /// `restart`: the VM runs, so a restart brings it now.
    Off {
        on: bool,
        restart: bool,
    },
    /// Waiting for the socket, the connection or the first frame.
    Connecting,
    Live,
    /// The connection ended; why, safe for a plain label.
    Ended(String),
}

/// The connection to a VM's screen, as the tab keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Link {
    Idle,
    Connecting,
    /// The first frame is in.
    Live,
    /// Why it ended, as the client said (untrusted).
    Ended(String),
}

/// What `info` said, if it saw the VM run: the list may already know it
/// has stopped or started since.
fn running_details<'a>(vm: &VmInfo, details: Option<&'a VmDetails>) -> Option<&'a VmDetails> {
    details.filter(|d| kind(&vm.state) != Kind::Stopped && kind(&d.vm.state) != Kind::Stopped)
}

/// The VNC socket to connect to: the VM runs and has one now.
pub fn screen_socket(vm: &VmInfo, details: Option<&VmDetails>) -> Option<PathBuf> {
    running_details(vm, details)?.vnc_socket.clone()
}

pub fn screen_page(vm: &VmInfo, details: Option<&VmDetails>, link: &Link) -> ScreenPage {
    let k = kind(&vm.state);
    if k == Kind::Stopped {
        return if vm.vnc {
            ScreenPage::Stopped
        } else {
            ScreenPage::Off {
                on: false,
                restart: false,
            }
        };
    }
    match link {
        Link::Live => return ScreenPage::Live,
        Link::Ended(why) => return ScreenPage::Ended(printable(why, 300)),
        Link::Connecting => return ScreenPage::Connecting,
        Link::Idle => {}
    }
    match running_details(vm, details) {
        Some(d) if d.vnc_socket.is_none() => ScreenPage::Off {
            on: vm.vnc,
            // A VM that does not run (paused...) gets no clean stop.
            restart: k == Kind::Running,
        },
        // Connecting, or `info` is not in yet.
        _ => ScreenPage::Connecting,
    }
}

/// A Screen tab page without the live screen. Descriptions are markup:
/// fixed text only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScreenStatus {
    pub icon: Option<&'static str>,
    pub title: &'static str,
    pub description: &'static str,
    /// The one action of the page, if any.
    pub button: Option<&'static str>,
}

/// Said wherever the live screen is turned on (SECURITY.md).
macro_rules! live_screen_risk {
    () => {
        "Everyone in the stallo group, and every program they run, can see and use a live screen, and what is typed there is not logged."
    };
}

pub fn screen_status(page: &ScreenPage) -> ScreenStatus {
    let (icon, title, description, button) = match page {
        ScreenPage::Stopped => (
            Some("video-display-symbolic"),
            "The VM Is Stopped",
            "Start the VM to see its screen.",
            Some("Start"),
        ),
        ScreenPage::Off { on: false, restart } => (
            Some("video-display-symbolic"),
            "Live Screen Is Off",
            if *restart {
                concat!(
                    "Turn on the live screen to see and use this VM here. The VM restarts for it. ",
                    live_screen_risk!()
                )
            } else {
                concat!(
                    "Turn on the live screen to see and use this VM here. It comes on when the VM starts. ",
                    live_screen_risk!()
                )
            },
            Some(if *restart {
                "Turn On Live Screen…"
            } else {
                "Turn On Live Screen"
            }),
        ),
        ScreenPage::Off { on: true, restart } => (
            Some("video-display-symbolic"),
            "Restart to Show the Screen",
            "The live screen is on, but the VM started before that. It shows here once the VM has stopped and started again.",
            restart.then_some("Restart…"),
        ),
        ScreenPage::Connecting => (None, "Connecting to the Screen", "", None),
        ScreenPage::Live => (None, "", "", None),
        ScreenPage::Ended(_) => (
            Some("network-offline-symbolic"),
            "Screen Disconnected",
            "The connection to the VM's screen ended.",
            Some("Reconnect"),
        ),
    };
    ScreenStatus {
        icon,
        title,
        description,
        button,
    }
}

/// The question before turning the live screen on in a running VM. Its
/// second answer turns it on without the restart.
pub fn confirm_live_screen(vm: &VmInfo) -> Confirm {
    Confirm {
        heading: "Turn On Live Screen?".to_owned(),
        body: format!(
            concat!(
                "The live screen comes with the VM's next start. Restart now to see it: {} shuts down and starts again, so save your work in it first. ",
                live_screen_risk!()
            ),
            printable(&vm.name, 64)
        ),
        button: "Restart Now",
    }
}

pub const LATER: &str = "At Next Start";

/// The question before the Overview switch turns the live screen on.
pub fn confirm_live_screen_switch(vm: &VmInfo) -> Confirm {
    Confirm {
        heading: "Turn On Live Screen?".to_owned(),
        body: format!(
            concat!("It comes on when {} starts next. ", live_screen_risk!()),
            printable(&vm.name, 64)
        ),
        button: "Turn On",
    }
}

/// The question before a restart that brings the live screen.
pub fn confirm_restart(vm: &VmInfo) -> Confirm {
    let name = printable(&vm.name, 64);
    Confirm {
        heading: format!("Restart {name}?"),
        body: format!("{name} shuts down and starts again, so save your work in it first."),
        button: "Restart",
    }
}

/// Whether the screen is view-only: it turns on when agent control does
/// (or is on when the tab opens), so a human and an agent do not fight
/// over the mouse. Otherwise the user's choice stays. `agent_before` is
/// `None` the first time.
pub fn view_only(now: bool, agent_before: Option<bool>, agent: bool) -> bool {
    now || (agent && agent_before != Some(true))
}

/// Where the framebuffer sits in the widget: its top-left corner and its
/// scale. Fit scales it to the widget; 1:1 never scales it up. Centred,
/// so the rest is letterbox.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Placement {
    pub x: f64,
    pub y: f64,
    pub scale: f64,
}

pub fn placement(widget: (f64, f64), fb: (u16, u16), fit: bool) -> Placement {
    let (w, h) = (f64::from(fb.0), f64::from(fb.1));
    let mut scale = (widget.0 / w).min(widget.1 / h);
    if !fit {
        scale = scale.min(1.0);
    }
    if !scale.is_finite() || scale <= 0.0 {
        scale = 1.0;
    }
    Placement {
        x: (widget.0 - w * scale) / 2.0,
        y: (widget.1 - h * scale) / 2.0,
        scale,
    }
}

/// The framebuffer pixel under widget point (`x`, `y`), kept on the
/// screen, and whether the point is on it (not on the letterbox).
pub fn to_guest(p: Placement, fb: (u16, u16), x: f64, y: f64) -> (u16, u16, bool) {
    let gx = ((x - p.x) / p.scale).floor();
    let gy = ((y - p.y) / p.scale).floor();
    let (w, h) = (f64::from(fb.0), f64::from(fb.1));
    let inside = (0.0..w).contains(&gx) && (0.0..h).contains(&gy);
    // `as` saturates; NaN becomes 0.
    let clamp = |v: f64, max: u16| (v.clamp(0.0, f64::from(max.saturating_sub(1)))) as u16;
    (clamp(gx, fb.0), clamp(gy, fb.1), inside)
}

/// The RFB button bit for a GDK button: left, middle, right.
pub fn button_bit(button: u32) -> Option<u8> {
    match button {
        1 => Some(1),
        2 => Some(2),
        3 => Some(4),
        _ => None,
    }
}

/// RFB wheel buttons: up, down.
const WHEEL_UP: u8 = 8;
const WHEEL_DOWN: u8 = 16;
/// Touchpad scrolling in pixels per wheel click.
// ponytail: a guess that feels right on one touchpad; tune when reported.
pub const SCROLL_PIXELS: f64 = 20.0;
/// Wheel clicks sent for one scroll event at most: each is a button
/// change the input queue must keep.
const MAX_CLICKS: f64 = 5.0;

/// The pointer as the guest sees it, in framebuffer pixels.
#[derive(Debug, Default)]
pub struct Mouse {
    x: u16,
    y: u16,
    buttons: u8,
    /// Scrolling not yet a whole wheel click.
    wheel: f64,
}

impl Mouse {
    fn at(&mut self, x: u16, y: u16) -> Input {
        (self.x, self.y) = (x, y);
        Input::Pointer {
            x,
            y,
            buttons: self.buttons,
        }
    }

    /// A move: sent while on the screen, or anywhere while a button is
    /// held (a drag that leaves it).
    pub fn moved(&mut self, x: u16, y: u16, inside: bool) -> Option<Input> {
        (inside || self.buttons != 0).then(|| self.at(x, y))
    }

    /// A button `bit` went down or up; `None` if that changes nothing.
    pub fn button(&mut self, x: u16, y: u16, bit: u8, down: bool) -> Option<Input> {
        let held = self.buttons;
        self.buttons = if down { held | bit } else { held & !bit };
        (self.buttons != held).then(|| self.at(x, y))
    }

    /// Wheel clicks for `delta` wheel steps (negative is up), each a press
    /// and a release. Whole clicks only; the rest waits for the next event.
    pub fn scroll(&mut self, x: u16, y: u16, delta: f64) -> Vec<Input> {
        self.wheel += delta;
        let clicks = self.wheel.trunc().clamp(-MAX_CLICKS, MAX_CLICKS);
        // A fling is capped, and its rest dropped.
        self.wheel = if clicks.abs() == MAX_CLICKS {
            0.0
        } else {
            self.wheel - clicks
        };
        let bit = if clicks < 0.0 { WHEEL_UP } else { WHEEL_DOWN };
        let up = self.at(x, y);
        let down = Input::Pointer {
            x,
            y,
            buttons: self.buttons | bit,
        };
        (0..clicks.abs() as usize)
            .flat_map(|_| [down, up])
            .collect()
    }

    /// Input stops here (view-only, or a new session): the guest lets go
    /// of any held button, and nothing carries over.
    pub fn let_go(&mut self) -> Option<Input> {
        let (x, y, held) = (self.x, self.y, self.buttons);
        *self = Mouse::default();
        (held != 0).then_some(Input::Pointer { x, y, buttons: 0 })
    }
}

/// Whether a frame may update the texture shown (`shown`: its serial and
/// size) in place, by its damage only: it is the very next frame, at the
/// same size. Otherwise it is drawn whole.
pub fn partial_redraw(shown: Option<(u64, u16, u16)>, serial: u64, size: (u16, u16)) -> bool {
    shown.is_some_and(|s| Some(s) == serial.checked_sub(1).map(|p| (p, size.0, size.1)))
}

pub const RELEASE_HINT: &str = "Ctrl+Alt+Esc releases the keyboard";
pub const GRAB_HINT: &str = "Click the screen to use it";

/// X keysyms the window looks for or sends.
const XK_ESCAPE: u32 = 0xff1b;
const XK_CONTROL_L: u32 = 0xffe3;
const XK_ALT_L: u32 = 0xffe9;
const XK_DELETE: u32 = 0xffff;
/// GTK hardware keycodes (evdev + 8) of left Ctrl, left Alt and Delete.
const KC_CONTROL_L: u32 = 37;
const KC_ALT_L: u32 = 64;
const KC_DELETE: u32 = 119;

/// What to do with a key press while the keyboard is grabbed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyPress {
    Send(Input),
    /// Ctrl+Alt+Esc: let go of the keyboard, after letting the guest go
    /// of the keys it holds. Esc itself never reaches the guest.
    Release(Vec<Input>),
}

/// The keys the guest holds down, by GTK keycode.
#[derive(Debug, Default)]
pub struct Keys(BTreeSet<u32>);

impl Keys {
    /// A key went down with Ctrl and Alt held (`ctrl`, `alt`) or not.
    pub fn press(&mut self, keycode: u32, keysym: u32, ctrl: bool, alt: bool) -> KeyPress {
        if keysym == XK_ESCAPE && ctrl && alt {
            return KeyPress::Release(self.release_all());
        }
        self.0.insert(keycode);
        KeyPress::Send(Input::Key {
            keycode,
            keysym,
            down: true,
        })
    }

    /// A key went up; `None` if the guest never saw it go down.
    pub fn release(&mut self, keycode: u32, keysym: u32) -> Option<Input> {
        self.0.remove(&keycode).then_some(Input::Key {
            keycode,
            keysym,
            down: false,
        })
    }

    /// Key-ups for every key the guest holds.
    pub fn release_all(&mut self) -> Vec<Input> {
        std::mem::take(&mut self.0)
            .into_iter()
            .map(|keycode| Input::Key {
                keycode,
                keysym: 0,
                down: false,
            })
            .collect()
    }
}

/// Ctrl+Alt+Del for the guest: down in order, up in reverse.
pub fn ctrl_alt_del() -> Vec<Input> {
    let keys = [
        (KC_CONTROL_L, XK_CONTROL_L),
        (KC_ALT_L, XK_ALT_L),
        (KC_DELETE, XK_DELETE),
    ];
    let key = |(keycode, keysym): (u32, u32), down| Input::Key {
        keycode,
        keysym,
        down,
    };
    keys.iter()
        .map(|&k| key(k, true))
        .chain(keys.iter().rev().map(|&k| key(k, false)))
        .collect()
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
        let r = row(&vm("running"), None);
        assert_eq!(r.name, "dev");
        assert_eq!((r.state, r.raw.as_str()), ("Running", "running"));
        assert_eq!(r.tone, Some("success"));
        assert!(!r.agent);
        assert_eq!(r.working, None);
        assert_eq!(r.label(), "dev, Running");
        let on = VmInfo {
            agent_control: true,
            ..vm("stopped")
        };
        let r = row(&on, Some(&Action::Take(None)));
        assert_eq!(r.tone, None);
        assert!(r.agent);
        assert_eq!(r.working, Some("Taking snapshot…"));
        assert_eq!(
            r.label(),
            "dev, Stopped, agent control on, Taking snapshot…"
        );
        assert_eq!(row(&vm("paused (disk full)"), None).tone, Some("warning"));
        assert_eq!(row(&vm("io-error"), None).tone, Some("error"));
        // Daemon text is cleaned and capped before it reaches a label.
        let odd = VmInfo {
            name: "a\u{202E}b\n".into(),
            ..vm(&"x".repeat(500))
        };
        let r = row(&odd, None);
        assert_eq!(r.name, "ab");
        assert_eq!(r.state, "Paused");
        assert_eq!(r.raw.len(), 64);
    }

    #[test]
    fn state_words() {
        for (state, word) in [
            ("stopped", "Stopped"),
            ("running", "Running"),
            ("running (no network)", "Running"),
            ("paused", "Paused"),
            ("paused (no network)", "Paused"),
            ("paused (disk full)", "Disk Full"),
            ("io-error", "Error"),
            ("internal-error", "Error"),
            ("guest-panicked", "Crashed"),
            ("unknown", "Not Responding"),
            // QEMU states on the way somewhere.
            ("save-vm", "Saving"),
            ("restore-vm", "Restoring"),
            ("inmigrate", "Restoring"),
            ("prelaunch", "Starting"),
            ("shutdown", "Shutting Down"),
            ("suspended (no network)", "Suspended"),
            // Anything else: the word for its kind, never the raw text.
            ("postmigrate", "Paused"),
            ("odd\u{1b}[31m", "Paused"),
            ("", "Paused"),
        ] {
            assert_eq!(state_word(state), word, "{state}");
        }
    }

    #[test]
    fn action_matrix() {
        const STOPPED: ActionSet = ActionSet {
            start: true,
            stop: false,
            force_off: false,
            reset: false,
            resume: false,
            primary: Op::Start,
            suggested: true,
        };
        const RUNNING: ActionSet = ActionSet {
            start: false,
            stop: true,
            force_off: true,
            reset: true,
            resume: false,
            primary: Op::Stop,
            suggested: false,
        };
        // No plain Stop: the daemon would quit QEMU without a shutdown.
        const HALTED: ActionSet = ActionSet {
            start: false,
            stop: false,
            force_off: true,
            reset: false,
            resume: true,
            primary: Op::Resume,
            suggested: true,
        };
        // Resume is no obvious next step for a VM that failed.
        const FAILED: ActionSet = ActionSet {
            suggested: false,
            ..HALTED
        };
        for (state, want) in [
            ("stopped", STOPPED),
            ("running", RUNNING),
            ("running (no network)", RUNNING),
            ("paused", HALTED),
            ("paused (no network)", HALTED),
            ("paused (disk full)", HALTED),
            ("save-vm", HALTED),
            ("io-error", FAILED),
            ("guest-panicked", FAILED),
            ("unknown", FAILED),
        ] {
            assert_eq!(actions(&vm(state), false), want, "{state}");
            // Blocked: nothing, but the layout stays.
            let busy = actions(&vm(state), true);
            assert!(Op::ALL.iter().all(|&op| !busy.allows(op)), "{state}");
            assert_eq!(busy.primary, want.primary, "{state}");
            assert_eq!(busy.suggested, want.suggested, "{state}");
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
        let take = Action::Take(None);
        assert!(!p.blocks("dev"));
        assert_eq!(p.action("dev"), None);
        assert!(p.start("dev", &take));
        assert!(
            !p.start("dev", &Action::Life(Op::Stop)),
            "one action per VM"
        );
        assert_eq!(p.action("dev"), Some(&take));
        assert!(p.start("web", &take));
        p.listed(t0 + s);
        assert!(p.blocks("dev"), "still running");
        p.finish("dev", t0 + 2 * s);
        p.listed(t0 + s);
        assert!(p.blocks("dev"), "that list was asked for before the end");
        p.listed(t0 + 2 * s);
        assert!(!p.blocks("dev"));
        assert_eq!(p.action("dev"), None);
        assert!(p.blocks("web"));
        assert!(p.start("dev", &take));
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
                "Stopped", "2", "2 GiB", "20 GiB", "Unknown", "Off", "None", "None"
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
                "Running",
                "2",
                "1536 MiB",
                "20 GiB",
                "1.5 GiB",
                "On",
                "127.0.0.1:8080 → 80\n[::1]:2222 → 22",
                "eth0  10.0.2.15/24\nevil  fe80::1/64",
            ]
        );
        let addresses =
            |d: Option<VmDetails>, state| values(facts(&vm(state), d.as_ref()))[7].clone();
        assert_eq!(addresses(None, "running"), "Unknown");
        assert_eq!(
            addresses(Some(details(None)), "running"),
            "Unknown (install qemu-guest-agent in the VM to see addresses)"
        );
        // The daemon cut the network of an internet VM.
        let cut = VmInfo {
            net: NetProfile::Internet,
            ..vm("running (no network)")
        };
        assert_eq!(
            values(facts(&cut, None))[..6],
            [
                "Running",
                "2",
                "2 GiB",
                "20 GiB",
                "Unknown",
                "Cut off until the VM restarts"
            ]
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
        assert_eq!(m.memory, "VM memory: 6 of 24 GiB");
        assert_eq!(m.disk, "Disk: 100 GiB free");
        assert!(!m.disk_low);
        let low = meter(&HostInfo {
            disk_free_bytes: 10 << 30,
            memory_used_mib: 30000,
            ..host.clone()
        });
        assert!(low.disk_low);
        assert_eq!(low.disk, "Disk: 10 GiB free. VMs pause below 20 GiB.");
        assert_eq!(low.memory, "VM memory: 29.3 of 24 GiB");
        // Rounded down, so never at or above the limit while below it.
        let edge = meter(&HostInfo {
            disk_free_bytes: (20 << 30) - 1,
            ..host.clone()
        });
        assert_eq!(edge.disk, "Disk: 19 GiB free. VMs pause below 20 GiB.");
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
        let rows = timeline(&vm("stopped"), &snaps, 10_000, None);
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
                "Just now · Disk only\nIts saved memory is missing, so it cannot be restored.",
                "Just now · Disk and memory (1.5 GiB)",
                "16 minutes ago · Disk and memory (412 MiB)",
                "2 hours ago · Disk only"
            ]
        );
        // Stopped: everything restores but a RAM snapshot whose RAM is gone.
        let blocks: Vec<_> = rows.iter().map(|r| r.restore_block).collect();
        assert!(blocks[0].unwrap().contains("missing"));
        assert_eq!(&blocks[1..], [None, None, None]);
        // Running: a disk-only snapshot needs the VM stopped first.
        for state in ["running", "paused", "paused (disk full)"] {
            let rows = timeline(&vm(state), &snaps, 10_000, None);
            assert!(
                rows[0].restore_block.unwrap().contains("missing"),
                "{state}"
            );
            assert_eq!(rows[1].restore_block, None, "{state}");
            assert!(
                rows[3].restore_block.unwrap().starts_with("Stop the VM"),
                "{state}"
            );
            // The reason is visible, not only on the greyed-out button.
            assert!(
                rows[3]
                    .subtitle
                    .ends_with("\nStop the VM to restore this snapshot."),
                "{state}"
            );
        }
        // An action on one snapshot shows on its row only.
        let working = |a: Action| {
            timeline(&vm("running"), &snaps, 10_000, Some(&a))
                .into_iter()
                .map(|r| r.working)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            working(Action::Restore("big".into())),
            [None, Some("Restoring…"), None, None]
        );
        assert_eq!(
            working(Action::Delete("disk".into())),
            [None, None, None, Some("Deleting…")]
        );
        assert_eq!(working(Action::Take(None)), [None; 4]);
        // Clock skew: never "in the future".
        assert_eq!(
            timeline(&vm("stopped"), &snaps[..1], 0, None)[0].subtitle,
            "Just now · Disk only"
        );
        // Daemon text is cleaned; the raw name goes back to the daemon.
        let odd = timeline(&vm("stopped"), &[snap("a\u{202E}b", 0, 0, 0)], 0, None);
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
        // The library's own check, in the window's words.
        for bad in [
            "1st",
            "with space",
            "a/b",
            "-x",
            &"x".repeat(65),
            "é",
            "a\u{1b}[31m",
        ] {
            let e = snapshot_name(bad, some).unwrap_err();
            assert!(e.starts_with("Use up to 64 letters"), "{bad}: {e}");
            assert!(stallo::config::validate_tag(bad).is_err());
        }

        // Prefilled with the next free name, which the check accepts.
        assert_eq!(suggested_name(None), "");
        assert_eq!(suggested_name(Some(&[])), "snap1");
        let taken = [snap("snap1", 0, 0, 0), snap("snap3", 0, 0, 0)];
        assert_eq!(suggested_name(Some(&taken)), "snap2");
        // Kept as suggested: the daemon picks the name.
        assert_eq!(
            snapshot_name(&suggested_name(Some(&taken)), Some(&taken)),
            Ok(None)
        );
        assert_eq!(
            snapshot_name("snap4", Some(&taken)),
            Ok(Some("snap4".into()))
        );
        assert_eq!(snapshot_name("snap1", None), Ok(Some("snap1".into())));
        // The limit is shown as the group description (markup): no markup.
        let why = take_block(Some(&full)).unwrap();
        assert!(!why.contains(['<', '>', '&']), "{why}");
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
        let wire = |a: Action| match a.requests("dev").as_slice() {
            [r] => serde_json::to_string(r).unwrap(),
            more => panic!("{more:?}"),
        };
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
        let title = |a: Action, e: &CallError| a.failed("dev", e).title;
        assert_eq!(
            title(Action::Take(None), &e),
            "Snapshot of dev still running"
        );
        assert!(
            Action::Take(None)
                .failed("dev", &e)
                .details
                .unwrap()
                .contains("may still finish")
        );
        assert_eq!(
            title(Action::Restore("s1".into()), &e),
            "Restore of s1 still running"
        );
        assert_eq!(
            title(Action::Delete("s1".into()), &e),
            "Deletion of s1 still running"
        );
        assert_eq!(
            Action::Delete("s\u{1b}1".into()).failed("dev", &CallError::Denied),
            Failure {
                title: "Could not delete s1".into(),
                details: Some(
                    "permission denied\n\nCheck that your account is in the stallo group.".into()
                ),
            }
        );
        assert_eq!(
            Action::Life(Op::Start).failed("dev", &e),
            Failure {
                title: "Could not start dev".into(),
                details: Some(
                    "no answer in time\n\nStallo may still be working on it. Look at the VM again in a moment."
                        .into()
                ),
            }
        );
        assert_eq!(
            title(Action::Life(Op::ForceOff), &e),
            "Could not force off dev"
        );
        for a in [
            Action::Life(Op::Start),
            Action::Take(None),
            Action::Restore("s".into()),
            Action::Delete("s".into()),
        ] {
            assert!(a.progress().ends_with('…'));
        }
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
    fn failures_have_details_and_next_steps() {
        let details = |m: &str| {
            failure("Could not x".into(), &CallError::Failed(m.into()))
                .details
                .unwrap()
        };
        // Daemon text in full (up to a cap), cleaned, no markup involved.
        let long = "a\u{202E}b".repeat(1500);
        assert_eq!(details(&long).len(), 2000);
        assert_eq!(details("no\u{1b}[31m way"), "no[31m way");
        for (msg, step) in [
            ("dev: guest agent not ready after 10s", "qemu-guest-agent"),
            (
                "the data disk is still below the 20 GiB floor; free space first",
                "Free up disk space",
            ),
            ("dev is busy; try again", "Wait until it is done"),
            ("dev is busy with a guest command; try again", "Wait until"),
            ("dev is busy with other input", "Wait until"),
            (
                "dev is in use by `stallo run`; try again when it ends",
                "Wait until",
            ),
            ("stallod is busy; try again", "Stallo is busy. Try again"),
        ] {
            let d = details(msg);
            assert!(d.starts_with(msg), "{d}");
            assert!(d.contains(step), "{msg}: {d}");
        }
        // "busy" alone, e.g. in a VM's name, is no known cause.
        for msg in ["busybox: no such VM", "cannot start busy-vm: bad disk"] {
            assert_eq!(details(msg), msg);
        }
        assert!(
            failure("x".into(), &CallError::NotRunning)
                .details
                .unwrap()
                .ends_with("Start the Stallo service, then try again.")
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

    fn details(vm: &VmInfo, state: &str, socket: Option<&str>) -> VmDetails {
        VmDetails {
            vm: VmInfo {
                state: state.into(),
                ..vm.clone()
            },
            addresses: None,
            disk_used_bytes: 0,
            vnc_socket: socket.map(PathBuf::from),
        }
    }

    #[test]
    fn screen_pages() {
        let sock = "/run/stallo/vnc/dev/vnc.sock";
        let on = |state: &str| VmInfo {
            vnc: true,
            ..vm(state)
        };
        let page = |vm: &VmInfo, d: Option<&VmDetails>, link: &Link| screen_page(vm, d, link);
        let off = |on, restart| ScreenPage::Off { on, restart };

        // Stopped wins over any connection.
        assert_eq!(page(&on("stopped"), None, &Link::Live), ScreenPage::Stopped);
        assert_eq!(page(&vm("stopped"), None, &Link::Idle), off(false, false));
        let running = on("running");
        let live = details(&running, "running", Some(sock));
        assert_eq!(screen_socket(&running, Some(&live)), Some(sock.into()));
        assert_eq!(screen_socket(&on("stopped"), Some(&live)), None);
        assert_eq!(
            page(&running, Some(&live), &Link::Idle),
            ScreenPage::Connecting
        );
        assert_eq!(
            page(&running, Some(&live), &Link::Connecting),
            ScreenPage::Connecting
        );
        assert_eq!(page(&running, Some(&live), &Link::Live), ScreenPage::Live);
        assert_eq!(
            page(
                &running,
                Some(&live),
                &Link::Ended("early eof\u{1b}[2J".into())
            ),
            ScreenPage::Ended("early eof[2J".into())
        );
        // `info` from before the start: wait for a fresh one.
        let old = details(&running, "stopped", None);
        assert_eq!(screen_socket(&running, Some(&old)), None);
        assert_eq!(
            page(&running, Some(&old), &Link::Idle),
            ScreenPage::Connecting
        );
        assert_eq!(page(&running, None, &Link::Idle), ScreenPage::Connecting);
        // Runs without a live screen: off, or on from the next start.
        let plain = vm("running");
        let none = details(&plain, "running", None);
        assert_eq!(page(&plain, Some(&none), &Link::Idle), off(false, true));
        assert_eq!(page(&running, Some(&none), &Link::Idle), off(true, true));
        // Paused: no clean restart.
        let paused = vm("paused");
        let none = details(&paused, "paused", None);
        assert_eq!(page(&paused, Some(&none), &Link::Idle), off(false, false));
        // Paused with a socket: the frozen screen.
        let paused = on("paused");
        let live = details(&paused, "paused", Some(sock));
        assert_eq!(screen_socket(&paused, Some(&live)), Some(sock.into()));
        // Turned off while running: the socket still serves until the stop.
        let plain = vm("running");
        let live = details(&plain, "running", Some(sock));
        assert_eq!(screen_socket(&plain, Some(&live)), Some(sock.into()));
    }

    #[test]
    fn screen_wording() {
        let status = |p: ScreenPage| screen_status(&p);
        assert_eq!(status(ScreenPage::Stopped).button, Some("Start"));
        assert!(
            status(ScreenPage::Stopped)
                .description
                .contains("Start the VM to see its screen")
        );
        for restart in [false, true] {
            let s = status(ScreenPage::Off { on: false, restart });
            assert!(s.description.contains("not logged"), "{restart}");
            assert!(s.button.unwrap().starts_with("Turn On Live Screen"));
        }
        assert!(
            status(ScreenPage::Off {
                on: false,
                restart: true
            })
            .description
            .contains("restarts")
        );
        assert_eq!(
            status(ScreenPage::Off {
                on: true,
                restart: true
            })
            .button,
            Some("Restart…")
        );
        assert_eq!(
            status(ScreenPage::Off {
                on: true,
                restart: false
            })
            .button,
            None
        );
        assert_eq!(status(ScreenPage::Connecting).button, None);
        assert_eq!(
            status(ScreenPage::Ended("x".into())).button,
            Some("Reconnect")
        );
        // Descriptions are markup.
        for p in [
            ScreenPage::Stopped,
            ScreenPage::Off {
                on: false,
                restart: false,
            },
            ScreenPage::Off {
                on: false,
                restart: true,
            },
            ScreenPage::Off {
                on: true,
                restart: true,
            },
            ScreenPage::Connecting,
            ScreenPage::Ended("<b>&".into()),
        ] {
            let d = status(p).description;
            assert!(!d.contains(['<', '&']), "{d}");
        }

        let odd = VmInfo {
            name: "de\u{1b}v".into(),
            ..vm("running")
        };
        let c = confirm_live_screen(&odd);
        assert_eq!(c.heading, "Turn On Live Screen?");
        assert!(
            c.body.contains("dev shuts down and starts again"),
            "{}",
            c.body
        );
        assert!(c.body.contains("not logged"));
        assert_eq!(c.button, "Restart Now");
        let c = confirm_live_screen_switch(&odd);
        assert_eq!(c.button, "Turn On");
        assert!(c.body.contains("when dev starts next"), "{}", c.body);
        assert!(c.body.contains("not logged"));
        let c = confirm_restart(&odd);
        assert_eq!(c.heading, "Restart dev?");
        assert_eq!(c.button, "Restart");
    }

    #[test]
    fn view_only_follows_agent_control() {
        // Opened with agent control on: view-only; off: not.
        assert!(view_only(false, None, true));
        assert!(!view_only(false, None, false));
        // The user turned it off: it stays off while agent control stays on.
        assert!(!view_only(false, Some(true), true));
        // Agent control turned on later: view-only again.
        assert!(view_only(false, Some(false), true));
        // The user's own choice stays when agent control goes off.
        assert!(view_only(true, Some(true), false));
        assert!(!view_only(false, Some(true), false));
    }

    #[test]
    fn pointer_mapping() {
        let fb = (1280, 800);
        // Fit, wider widget: scaled 0.5, letterbox left and right.
        let p = placement((1000.0, 400.0), fb, true);
        assert_eq!(
            p,
            Placement {
                x: 180.0,
                y: 0.0,
                scale: 0.5
            }
        );
        assert_eq!(to_guest(p, fb, 180.0, 0.0), (0, 0, true));
        assert_eq!(to_guest(p, fb, 500.0, 200.0), (640, 400, true));
        assert_eq!(to_guest(p, fb, 819.9, 399.9), (1279, 799, true));
        // On the letterbox: kept on the edge, but not on the screen.
        assert_eq!(to_guest(p, fb, 100.0, 50.0), (0, 100, false));
        assert_eq!(to_guest(p, fb, 990.0, 50.0), (1279, 100, false));
        // Fit, taller widget: letterbox above and below; scales up too.
        let p = placement((2560.0, 2000.0), fb, true);
        assert_eq!((p.x, p.y, p.scale), (0.0, 200.0, 2.0));
        assert_eq!(to_guest(p, fb, 2559.0, 1799.0), (1279, 799, true));
        assert_eq!(to_guest(p, fb, 10.0, 100.0), (5, 0, false));
        // 1:1 in a larger widget: not scaled, centred.
        let p = placement((1480.0, 1000.0), fb, false);
        assert_eq!((p.x, p.y, p.scale), (100.0, 100.0, 1.0));
        assert_eq!(to_guest(p, fb, 100.0, 100.0), (0, 0, true));
        assert_eq!(to_guest(p, fb, 740.5, 500.5), (640, 400, true));
        assert_eq!(to_guest(p, fb, 99.0, 100.0), (0, 0, false));
        // 1:1 never scales up, but down if it must.
        assert_eq!(placement((640.0, 400.0), fb, false).scale, 0.5);
        // No size yet: no division by zero.
        let p = placement((0.0, 0.0), fb, true);
        assert!(p.scale.is_finite());
        assert!(!to_guest(p, fb, f64::NAN, 5.0).2);
    }

    #[test]
    fn mouse_buttons_and_wheel() {
        let at = |x, y, buttons| Input::Pointer { x, y, buttons };
        assert_eq!(button_bit(1), Some(1));
        assert_eq!(button_bit(2), Some(2));
        assert_eq!(button_bit(3), Some(4));
        assert_eq!(button_bit(8), None);
        let mut m = Mouse::default();
        // Hover on the screen only; a drag goes on outside it.
        assert_eq!(m.moved(5, 6, true), Some(at(5, 6, 0)));
        assert_eq!(m.moved(0, 6, false), None);
        assert_eq!(m.button(5, 6, 1, true), Some(at(5, 6, 1)));
        assert_eq!(m.button(5, 6, 1, true), None, "no change");
        assert_eq!(m.moved(0, 9, false), Some(at(0, 9, 1)));
        assert_eq!(m.button(0, 9, 4, true), Some(at(0, 9, 5)));
        assert_eq!(m.button(0, 9, 1, false), Some(at(0, 9, 4)));
        // The wheel: a click is a press and a release, held buttons kept.
        assert_eq!(m.scroll(1, 2, -1.0), [at(1, 2, 4 | 8), at(1, 2, 4)]);
        assert_eq!(m.scroll(1, 2, 1.0), [at(1, 2, 4 | 16), at(1, 2, 4)]);
        // A touchpad: fractions add up to a click.
        assert!(m.scroll(1, 2, 0.4).is_empty());
        assert!(m.scroll(1, 2, 0.4).is_empty());
        assert_eq!(m.scroll(1, 2, 0.4).len(), 2);
        // A fling is capped, and its rest dropped.
        assert_eq!(m.scroll(1, 2, -40.0).len(), 10);
        assert!(m.scroll(1, 2, 0.9).is_empty());
    }

    #[test]
    fn no_phantom_buttons() {
        let mut m = Mouse::default();
        // View-only turns on mid-drag: the guest lets go where it was.
        m.button(7, 8, 1, true);
        m.moved(9, 10, false);
        m.scroll(9, 10, 0.5);
        assert_eq!(
            m.let_go(),
            Some(Input::Pointer {
                x: 9,
                y: 10,
                buttons: 0
            })
        );
        // Nothing carries over: no held button, no half wheel click.
        assert_eq!(m.let_go(), None);
        assert!(m.scroll(9, 10, 0.5).is_empty());
        assert_eq!(
            m.moved(1, 1, true),
            Some(Input::Pointer {
                x: 1,
                y: 1,
                buttons: 0
            })
        );
        // Nothing held: nothing to send.
        assert_eq!(Mouse::default().let_go(), None);
    }

    #[test]
    fn partial_redraws() {
        assert!(partial_redraw(Some((4, 1280, 800)), 5, (1280, 800)));
        // A skipped frame, a resize, a new session or nothing shown yet.
        assert!(!partial_redraw(Some((3, 1280, 800)), 5, (1280, 800)));
        assert!(!partial_redraw(Some((4, 1280, 800)), 5, (1024, 768)));
        assert!(!partial_redraw(Some((9, 1280, 800)), 1, (1280, 800)));
        assert!(!partial_redraw(None, 1, (1280, 800)));
        assert!(!partial_redraw(Some((0, 1, 1)), 0, (1, 1)));
    }

    #[test]
    fn keys_and_the_release_combination() {
        let key = |keycode, keysym, down| Input::Key {
            keycode,
            keysym,
            down,
        };
        let mut k = Keys::default();
        // Plain Esc, Ctrl+Esc and Alt+Esc go to the guest.
        assert_eq!(
            k.press(9, XK_ESCAPE, false, false),
            KeyPress::Send(key(9, XK_ESCAPE, true))
        );
        assert_eq!(k.release(9, XK_ESCAPE), Some(key(9, XK_ESCAPE, false)));
        assert_eq!(
            k.press(9, XK_ESCAPE, true, false),
            KeyPress::Send(key(9, XK_ESCAPE, true))
        );
        assert_eq!(
            k.press(9, XK_ESCAPE, false, true),
            KeyPress::Send(key(9, XK_ESCAPE, true))
        );
        let _ = k.release_all();
        // Ctrl and Alt go down to the guest, then Esc with both held lets
        // go: the guest gets Ctrl and Alt up, never Esc.
        assert_eq!(
            k.press(KC_CONTROL_L, XK_CONTROL_L, false, false),
            KeyPress::Send(key(KC_CONTROL_L, XK_CONTROL_L, true))
        );
        assert!(matches!(
            k.press(KC_ALT_L, XK_ALT_L, true, false),
            KeyPress::Send(_)
        ));
        assert_eq!(
            k.press(9, XK_ESCAPE, true, true),
            KeyPress::Release(vec![key(KC_CONTROL_L, 0, false), key(KC_ALT_L, 0, false)])
        );
        // Their key-ups come after the release: nothing left to send.
        assert_eq!(k.release(9, XK_ESCAPE), None);
        assert_eq!(k.release(KC_CONTROL_L, XK_CONTROL_L), None);
        assert!(k.release_all().is_empty());
    }

    #[test]
    fn ctrl_alt_del_order() {
        let keys: Vec<(u32, bool)> = ctrl_alt_del()
            .into_iter()
            .map(|i| match i {
                Input::Key { keycode, down, .. } => (keycode, down),
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(
            keys,
            [
                (37, true),
                (64, true),
                (119, true),
                (119, false),
                (64, false),
                (37, false)
            ]
        );
        // The rfb client's table knows them (evdev = keycode - 8).
        for (keycode, _) in keys {
            assert!(crate::rfb::qemu_scancode(keycode - 8).is_some());
        }
    }

    #[test]
    fn live_screen_actions() {
        let wire = |a: Action| {
            a.requests("dev")
                .iter()
                .map(|r| serde_json::to_string(r).unwrap())
                .collect::<Vec<_>>()
        };
        let set = r#"{"op":"set_vnc","name":"dev","on":true}"#;
        let stop = r#"{"op":"stop","name":"dev","force":false}"#;
        let start = r#"{"op":"start","name":"dev","wait":false}"#;
        assert_eq!(wire(Action::LiveScreen(true)), [set]);
        assert_eq!(
            wire(Action::LiveScreen(false)),
            [r#"{"op":"set_vnc","name":"dev","on":false}"#]
        );
        assert_eq!(
            wire(Action::Restart { live_screen: true }),
            [set, stop, start]
        );
        assert_eq!(wire(Action::Restart { live_screen: false }), [stop, start]);
        for a in [
            Action::LiveScreen(true),
            Action::LiveScreen(false),
            Action::Restart { live_screen: true },
        ] {
            assert!(a.lifecycle());
            assert_eq!(a.limit(), Op::Stop.limit());
            assert!(a.progress().ends_with('…'));
            assert_eq!(a.done("dev", &serde_json::Value::Null), None);
        }
        assert!(!Action::Take(None).lifecycle());
        assert_eq!(
            Action::LiveScreen(true)
                .failed("dev", &CallError::Timeout)
                .title,
            "Could not turn on the live screen of dev"
        );
        assert_eq!(
            Action::LiveScreen(false)
                .failed("dev", &CallError::Timeout)
                .title,
            "Could not turn off the live screen of dev"
        );
        // Restart with the live screen: which request failed decides.
        let both = Action::Restart { live_screen: true };
        let title = |step| {
            both.failed_at(step)
                .failed("dev", &CallError::Timeout)
                .title
        };
        assert_eq!(
            title(0),
            "Could not turn on the live screen and restart dev"
        );
        assert_eq!(title(1), "Could not restart dev");
        assert_eq!(title(2), "Could not restart dev");
        assert_eq!(Action::Take(None).failed_at(0), Action::Take(None));
        assert_eq!(
            Action::Restart { live_screen: false }
                .failed("dev", &CallError::Timeout)
                .title,
            "Could not restart dev"
        );
        // An action on the VM holds its row and its buttons.
        let r = row(&vm("running"), Some(&Action::Restart { live_screen: true }));
        assert_eq!(r.working, Some("Restarting…"));
    }
}
