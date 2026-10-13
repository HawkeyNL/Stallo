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
use std::net::IpAddr;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Stdio;

use anyhow::{Context, Result, bail};
use tokio::process::{Child, Command};

use crate::config::{PortForward, VmConfig};

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
