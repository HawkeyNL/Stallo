//! Plain-Rust view-model: what the window should show, decided from facts
//! gathered elsewhere (no GTK, no I/O), so every case is unit-testable.

use std::path::PathBuf;
use std::time::Duration;

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
    Connected {
        vms: usize,
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
        Some(Ok(vms)) => Onboarding::Connected { vms: *vms },
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
        assert_eq!(onboarding(&explicit), Onboarding::Connected { vms: 2 });
        // A dev daemon while production is closed to us: use dev mode.
        let dev = Probe {
            production: Production::Denied,
            dev_up: true,
            group: NOT_LISTED,
            list: Some(Ok(0)),
            ..probe()
        };
        assert_eq!(socket(&dev), probe().dev);
        assert_eq!(onboarding(&dev), Onboarding::Connected { vms: 0 });
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
            Onboarding::Connected { vms: 3 }
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

        let (connected, back) = onboarding.next(Onboarding::Connected { vms: 1 });
        assert!(!back);
        assert!(!connected.polls(true), "connected: no polling");

        // Lost: keep the page, show the banner, poll until it is back.
        let (lost, back) = connected.next(Onboarding::DaemonStopped);
        assert!(!back);
        assert_eq!(lost.page, Onboarding::Connected { vms: 1 });
        assert!(lost.reconnecting);
        assert!(lost.polls(true));
        assert!(!lost.polls(false));
        let (lost, _) = lost.next(Onboarding::Unreachable("x".into()));
        assert!(lost.reconnecting);

        let (again, back) = lost.next(Onboarding::Connected { vms: 2 });
        assert!(back, "toast on recovery");
        assert_eq!(again.page, Onboarding::Connected { vms: 2 });
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
        let connected = View {
            page: Onboarding::Connected { vms: 1 },
            reconnecting: false,
        };
        assert!(connected.next(down).0.reconnecting);
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
                            page == Onboarding::Connected { vms: 1 },
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
}
