//! The `internet` profile: passt, the guest's network card and port
//! forwards.
//!
//! passt runs as the daemon's user, in the VM's cgroup, and talks to QEMU
//! over a connected `socketpair`. passt gets one end (`--fd`) and QEMU the
//! other (`-netdev stream,addr.type=fd`). No socket file exists, QEMU never
//! calls `connect()` (its seccomp filter forbids it), and passt exits when
//! QEMU closes its end.
//!
//! passt has no egress filter of its own. The host's `inet stallo`
//! nftables table does the isolation: it drops every connection that a
//! process of the daemon's user opens to host, private, link-local and
//! multicast addresses. See `docs/network-verification.md`.

use std::fs::File;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::process::{Child, Command};

use crate::config::{NetProfile, PortForward, VmConfig};
use crate::vm::Manager;

pub const PASST: &str = "/usr/bin/passt";

/// The DNS server address passt hands the guest. passt relays queries to
/// it to the configured public resolver (`net.dns`), never to the host's
/// own resolver. Link-local, so it can never be a real internet server.
pub const GUEST_DNS: &str = "169.254.1.53";

/// Most open files for passt. Each guest flow is a host socket and a
/// conntrack entry shared with the whole host; passt would otherwise raise
/// its limit to the hard limit.
pub const PASST_MAX_FILES: libc::rlim_t = 4096;

/// passt's share of the VM cgroup's memory (it used 18-21 MiB in the lab).
pub const PASST_MEMORY_MIB: u64 = 64;

/// How often the isolation probe repeats while `internet` VMs run.
pub const RECHECK: Duration = Duration::from_secs(2);

/// Fails unless the host isolates this user's traffic: passt is installed
/// and the `inet stallo` nftables table drops what it must.
///
/// The probe sends one UDP datagram each to its own `127.0.0.1` and `::1`
/// sockets, to `10.255.255.1:9` and to `127.0.0.53:54`. The table drops
/// each in the output hook, which fails `sendto` with `EPERM` at once
/// (a dropped TCP SYN would only time out). Anything else, including a
/// datagram that was sent, fails the check. It takes microseconds.
pub fn check_isolation() -> Result<()> {
    probe().context("isolation unavailable")
}

fn probe() -> Result<()> {
    if !Path::new(PASST).exists() {
        bail!("{PASST} is missing; install the passt package");
    }
    // Receivers for the loopback probes; whatever reaches them is dropped
    // with them.
    let own4 = UdpSocket::bind("127.0.0.1:0").context("cannot bind a 127.0.0.1 probe socket")?;
    let own6 = UdpSocket::bind("[::1]:0").context("cannot bind a ::1 probe socket")?;
    let targets = [
        own4.local_addr()?,
        own6.local_addr()?,
        // A private range, never local.
        SocketAddr::from(([10, 255, 255, 1], 9)),
        // The DNS exception is for port 53 only.
        SocketAddr::from(([127, 0, 0, 53], 54)),
    ];
    // One at a time, loopback first: without the table the probe stops
    // at the first datagram, before anything could leave the host.
    for to in targets {
        verdict(&[(to, send_one(to))])?;
    }
    Ok(())
}

fn send_one(to: SocketAddr) -> io::Result<()> {
    let any: SocketAddr = if to.is_ipv4() {
        ([0, 0, 0, 0], 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    UdpSocket::bind(any)?
        .send_to(b"stallo isolation probe", to)
        .map(drop)
}

/// Every probe must have failed with `EPERM`.
fn verdict(results: &[(SocketAddr, io::Result<()>)]) -> Result<()> {
    for (to, r) in results {
        match r {
            Err(e) if e.raw_os_error() == Some(libc::EPERM) => {}
            Ok(()) => {
                bail!("a probe datagram to {to} was sent; the stallo nftables table is not loaded")
            }
            Err(e) => bail!("the probe to {to} failed with \"{e}\" instead of EPERM"),
        }
    }
    Ok(())
}

/// Repeats the probe every [`RECHECK`] while `internet` VMs run, and pauses
/// them all when it fails: the table can be flushed at runtime (`nft flush
/// ruleset`). `stallo resume` probes again before it continues a VM.
pub async fn watchdog(manager: Arc<Manager>) {
    let mut tick = tokio::time::interval(RECHECK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let vms: Vec<_> = manager
            .all_running()
            .into_iter()
            .filter(|vm| vm.config.net == NetProfile::Internet)
            .collect();
        if vms.is_empty() {
            continue;
        }
        let Err(e) = check_isolation() else {
            continue;
        };
        for vm in vms {
            match vm.pause_isolation_lost().await {
                Ok(true) => tracing::error!("{}: paused: {e:#}", vm.config.name),
                Ok(false) => {}
                Err(err) => tracing::error!("{}: pause failed: {err:#}", vm.config.name),
            }
        }
    }
}

/// passt's arguments. `fd` is passt's end of the socketpair; guest DNS
/// goes to `dns`.
pub fn passt_args(forwards: &[PortForward], fd: RawFd, dns: IpAddr) -> Vec<String> {
    let mut args: Vec<String> = [
        "--foreground",
        // Warnings and errors only; the log is the VM's passt.log.
        "--quiet",
        "--fd",
        &fd.to_string(),
        // Never map a guest address to the host's loopback or global
        // address (the table would drop it anyway; defence in depth).
        "--map-host-loopback",
        "none",
        "--map-guest-addr",
        "none",
        "--dns-forward",
        GUEST_DNS,
        "--dns-host",
        &dns.to_string(),
        // The host's search domains (tailnet, LAN) stay on the host.
        "--search",
        "none",
        "-u",
        "none",
    ]
    .map(str::to_owned)
    .to_vec();
    if forwards.is_empty() {
        args.extend(["-t".to_owned(), "none".to_owned()]);
    }
    for f in forwards {
        args.push("-t".to_owned());
        args.push(format!("{}/{}:{}", f.bind, f.host, f.guest));
    }
    args
}

/// The guest's MAC address, fixed per VM: QEMU's prefix `52:54:00` and the
/// first three bytes of the VM's random uuid.
pub fn mac(cfg: &VmConfig) -> String {
    let h = &cfg.uuid;
    format!("52:54:00:{}:{}:{}", &h[0..2], &h[2..4], &h[4..6])
}

/// Parses a `--forward` value: `HOST:GUEST`, or `PORT` for the same port
/// on both sides, bound to `bind`.
pub fn parse_forward(spec: &str, bind: IpAddr) -> Result<PortForward> {
    let port = |s: &str| -> Result<u16> {
        s.parse()
            .with_context(|| format!("invalid port {s:?} in --forward {spec:?}"))
    };
    let (host, guest) = match spec.split_once(':') {
        Some((h, g)) => (port(h)?, port(g)?),
        None => (port(spec)?, port(spec)?),
    };
    let f = PortForward { bind, host, guest };
    f.validate()?;
    Ok(f)
}

/// A connected pair of stream sockets: (passt's end, QEMU's end). Both are
/// close-on-exec until [`inherit_on_exec`] hands one to a child.
pub fn socketpair() -> Result<(OwnedFd, OwnedFd)> {
    let (a, b) = UnixStream::pair().context("cannot create the passt socket pair")?;
    Ok((a.into(), b.into()))
}

/// Makes `cmd`'s child keep `fd` open across `exec`, under the same number.
/// The parent's copy closes when `cmd` is dropped.
pub fn inherit_on_exec(cmd: &mut Command, fd: OwnedFd) {
    // SAFETY: the closure runs in the forked child before exec and makes
    // one fcntl syscall on an fd it owns: no allocation, locking or
    // logging. Clearing FD_CLOEXEC in the child leaves the parent's copy
    // close-on-exec, so no other child inherits it.
    #[allow(unsafe_code)]
    unsafe {
        cmd.pre_exec(move || {
            if libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// Starts passt for `cfg` in the VM cgroup `cgroup`, with `fd` as its end
/// of the socketpair. passt's messages go to `log`.
pub fn spawn_passt(
    cfg: &VmConfig,
    dns: IpAddr,
    fd: OwnedFd,
    cgroup: &Path,
    log: File,
) -> Result<Child> {
    if !Path::new(PASST).exists() {
        bail!("{PASST} is missing; install the passt package");
    }
    let mut cmd = Command::new(PASST);
    cmd.args(passt_args(&cfg.forwards, fd.as_raw_fd(), dns))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(log)
        // Like QEMU: a Ctrl-C meant for a foreground daemon must not reach
        // it.
        .process_group(0);
    crate::cgroup::move_on_exec(&mut cmd, cgroup)?;
    inherit_on_exec(&mut cmd, fd);
    // SAFETY: runs in the forked child before exec; one setrlimit syscall
    // on a stack value, nothing else.
    #[allow(unsafe_code)]
    unsafe {
        cmd.pre_exec(|| {
            let lim = libc::rlimit {
                rlim_cur: PASST_MAX_FILES,
                rlim_max: PASST_MAX_FILES,
            };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &lim) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    cmd.spawn().context("cannot start passt")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NetProfile;

    fn vm() -> VmConfig {
        VmConfig {
            name: "web".into(),
            uuid: "4f1c2b9e-0d3a-4c5e-8f7a-1b2c3d4e5f60".into(),
            image: "ubuntu-26.04".into(),
            vcpus: 2,
            memory_mib: 2048,
            disk_gib: 20,
            net: NetProfile::Internet,
            agent_control: false,
            throwaway_of: None,
            forwards: vec![],
        }
    }

    #[test]
    fn golden_passt_args() {
        let base = "--foreground --quiet --fd 7 --map-host-loopback none \
                    --map-guest-addr none --dns-forward 169.254.1.53 \
                    --dns-host 9.9.9.9 --search none -u none";
        let dns = IpAddr::from([9, 9, 9, 9]);
        assert_eq!(passt_args(&[], 7, dns).join(" "), format!("{base} -t none"));
        let lo = "127.0.0.1".parse().unwrap();
        let f = [
            parse_forward("8080:80", lo).unwrap(),
            parse_forward("2222:22", "::1".parse().unwrap()).unwrap(),
        ];
        assert_eq!(
            passt_args(&f, 7, dns).join(" "),
            format!("{base} -t 127.0.0.1/8080:80 -t ::1/2222:22")
        );
    }

    #[test]
    fn forward_specs() {
        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(
            parse_forward("8080:80", lo).unwrap(),
            PortForward {
                bind: lo,
                host: 8080,
                guest: 80
            }
        );
        assert_eq!(parse_forward("3000", lo).unwrap().guest, 3000);
        for bad in [
            "80",
            "1024:80",
            "8080:0",
            "8080:",
            ":80",
            "x:80",
            "70000:80",
            "8080:80:1",
        ] {
            assert!(parse_forward(bad, lo).is_err(), "{bad}");
        }
        assert!(parse_forward("8080:80", "0.0.0.0".parse().unwrap()).is_err());
    }

    #[test]
    fn mac_is_stable_per_vm() {
        assert_eq!(mac(&vm()), "52:54:00:4f:1c:2b");
    }

    #[test]
    fn verdict_needs_eperm_everywhere() {
        let to: SocketAddr = ([10, 255, 255, 1], 9).into();
        let eperm = || Err(io::Error::from_raw_os_error(libc::EPERM));
        verdict(&[(to, eperm()), (to, eperm())]).unwrap();
        let sent = verdict(&[(to, eperm()), (to, Ok(()))]).unwrap_err();
        assert!(sent.to_string().contains("not loaded"), "{sent}");
        // A timeout or "unreachable" proves nothing about the table.
        for errno in [
            libc::ENETUNREACH,
            libc::EHOSTUNREACH,
            libc::EACCES,
            libc::EAGAIN,
        ] {
            let r = verdict(&[(to, Err(io::Error::from_raw_os_error(errno)))]);
            assert!(r.is_err(), "{errno}");
        }
        assert!(verdict(&[]).is_ok());
    }

    /// Without the table (as on a dev host or in CI), the probe fails.
    /// Only loopback targets: nothing leaves the machine.
    #[test]
    fn unfiltered_loopback_fails_the_probe() {
        let own = UdpSocket::bind("127.0.0.1:0").unwrap();
        let to = own.local_addr().unwrap();
        assert!(verdict(&[(to, send_one(to))]).is_err());
    }

    /// The child sees the socket under the parent's number; nothing else
    /// leaks.
    #[tokio::test]
    async fn the_child_inherits_only_its_end() {
        let (mine, theirs) = socketpair().unwrap();
        let n = theirs.as_raw_fd();
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg(format!(
                "readlink /proc/self/fd/{n}; test -e /proc/self/fd/{} || echo closed",
                mine.as_raw_fd()
            ))
            .stdout(Stdio::piped());
        inherit_on_exec(&mut cmd, theirs);
        let out = cmd.output().await.unwrap();
        let out = String::from_utf8(out.stdout).unwrap();
        assert!(out.starts_with("socket:["), "{out}");
        assert!(out.ends_with("closed\n"), "{out}");
    }
}
