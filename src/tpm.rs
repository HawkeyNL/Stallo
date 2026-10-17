//! swtpm: the TPM 2.0 of a Windows VM (Windows 11 needs one).
//!
//! The daemon starts one swtpm per Windows VM, before QEMU and in the VM's
//! cgroup, and connects the two with a `socketpair` as in net.rs: swtpm
//! gets one end as its control channel (`--ctrl type=unixio,clientfd=N`),
//! QEMU the other (`-chardev socket,fd=M`, see `qemu::argv`). No socket
//! file exists and neither side calls `connect()`. With `,terminate` swtpm
//! exits when QEMU closes its end; the VM's cgroup takes whatever is left.
//!
//! The TPM state lives in `<vm>/tpm/` (0700) and goes with the VM. swtpm
//! creates it at the first start (no `swtpm_setup`, no EK certificates, no
//! state encryption: Windows Setup only needs a TPM 2.0, and the VM
//! directory is private already).
//!
//! swtpm parses TPM commands from the guest, so it is confined like QEMU:
//! Landlock to its own state directory ([`confine::swtpm_rules`]), the
//! seccomp filter of `confine_on_exec`, and in production the AppArmor
//! profile `stallo-swtpm`. No `mode=` on `--tpmstate`: swtpm would
//! `fchmod` its files, which the filter denies; the directory is 0700.

use std::fs::File;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::Path;
use std::process::Stdio;

use anyhow::{Context, Result};
use tokio::process::{Child, Command};

use crate::config::Mode;
use crate::{confine, net};

pub const SWTPM: &str = "/usr/bin/swtpm";
/// swtpm's share of the VM cgroup's memory (it uses about 5 MiB).
pub const MEMORY_MIB: u64 = 32;
/// The TPM state directory, in the VM directory.
pub const DIR: &str = "tpm";
/// swtpm's messages, in the VM directory.
pub const LOG: &str = "swtpm.log";

/// swtpm's arguments. `fd` is swtpm's end of the socketpair. swtpm splits
/// option values at commas and has no escape, so a state path with one is
/// refused.
pub fn args(tpm_dir: &Path, fd: RawFd) -> Result<Vec<String>> {
    let dir = tpm_dir
        .to_str()
        .filter(|d| !d.contains(',') && !d.chars().any(char::is_control))
        .with_context(|| format!("unusable TPM state path {}", tpm_dir.display()))?;
    Ok([
        "socket",
        "--tpm2",
        "--tpmstate",
        &format!("dir={dir}"),
        "--ctrl",
        &format!("type=unixio,clientfd={fd},terminate"),
        // Errors to stderr, the VM's swtpm.log. (`fd=2` makes swtpm 0.10
        // close its stderr and fail.)
        "--log",
        "level=1",
    ]
    .map(str::to_owned)
    .to_vec())
}

/// Starts swtpm on `tpm_dir` in the VM cgroup `cgroup`, with `fd` as its
/// end of the socketpair, confined (see the module docs). Its messages go
/// to `log`. In production the spawn fails unless swtpm runs under the
/// enforced `stallo-swtpm` profile; the caller's cgroup cleanup kills it.
pub fn spawn(tpm_dir: &Path, fd: OwnedFd, cgroup: &Path, log: File, mode: Mode) -> Result<Child> {
    let mut cmd = Command::new(SWTPM);
    cmd.args(args(tpm_dir, fd.as_raw_fd())?)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(log)
        // Like QEMU: a Ctrl-C meant for a foreground daemon must not reach
        // it.
        .process_group(0);
    // Order matters: the cgroup and AppArmor hooks open files the ruleset
    // denies.
    crate::cgroup::move_on_exec(&mut cmd, cgroup)?;
    net::inherit_on_exec(&mut cmd, fd);
    if mode == Mode::Production {
        confine::apparmor_on_exec(&mut cmd, confine::SWTPM_PROFILE);
    }
    confine::confine_on_exec(&mut cmd, confine::build(&confine::swtpm_rules(tpm_dir))?);
    let child = cmd.spawn().with_context(|| match mode {
        Mode::Production => format!(
            "cannot start swtpm (is the AppArmor profile {} loaded?)",
            confine::SWTPM_PROFILE
        ),
        Mode::Dev => "cannot start swtpm".to_owned(),
    })?;
    if mode == Mode::Production {
        let pid = child
            .id()
            .expect("a child that was not waited for has a pid");
        confine::check_profile(pid, confine::SWTPM_PROFILE)?;
    }
    Ok(child)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    #[test]
    fn golden_args() {
        let a = args(Path::new("/d/vms/win/tpm"), 7).unwrap();
        assert_eq!(
            a.join(" "),
            "socket --tpm2 --tpmstate dir=/d/vms/win/tpm \
             --ctrl type=unixio,clientfd=7,terminate --log level=1"
        );
        // A control channel on the inherited fd only: no data socket, no
        // TCP, no socket file, no mode change.
        let all = a.join(" ");
        for bad in ["--server", "--port", "tcp", "path=", "mode=", "fd=2"] {
            assert!(!all.contains(bad), "{bad}");
        }
        assert!(args(Path::new("/d/a,b/tpm"), 7).is_err());
        assert!(args(Path::new("/d/a\nb/tpm"), 7).is_err());
    }

    /// The real swtpm under its Landlock rules and the seccomp filter: it
    /// answers on the control channel, creates its state in its own
    /// directory and exits when the channel closes.
    #[tokio::test]
    async fn swtpm_runs_confined() {
        if !Path::new(SWTPM).exists() {
            eprintln!("skipped: {SWTPM} is missing");
            return;
        }
        if !confine::available() {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let dir = std::fs::canonicalize(tmp.path()).unwrap().join(DIR);
        crate::paths::ensure_private_dir(&dir).unwrap();
        let (mine, theirs) = net::socketpair().unwrap();
        let mut cmd = Command::new(SWTPM);
        cmd.args(args(&dir, theirs.as_raw_fd()).unwrap())
            .stdin(Stdio::null())
            .stdout(Stdio::null());
        net::inherit_on_exec(&mut cmd, theirs);
        confine::confine_on_exec(
            &mut cmd,
            confine::build(&confine::swtpm_rules(&dir)).unwrap(),
        );
        let mut child = cmd.spawn().unwrap();
        drop(cmd);

        let mut ctrl = UnixStream::from(mine);
        ctrl.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut ask = |cmd: &[u8], len: usize| {
            ctrl.write_all(cmd).unwrap();
            let mut reply = vec![0; len];
            ctrl.read_exact(&mut reply).unwrap();
            reply
        };
        // CMD_GET_CAPABILITY, then CMD_INIT; both answer TPM_SUCCESS (0).
        assert_eq!(ask(&1u32.to_be_bytes(), 8)[..4], [0; 4]);
        assert_eq!(ask(&[0, 0, 0, 2, 0, 0, 0, 0], 4), [0; 4]);
        assert!(dir.join("tpm2-00.permall").exists());
        drop(ctrl);
        let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
            .await
            .expect("swtpm did not exit when its channel closed")
            .unwrap();
        assert!(status.success(), "{status}");
    }
}
