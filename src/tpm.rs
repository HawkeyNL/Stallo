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

use std::fs::{self, File};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{Context, Result, ensure};
use tokio::process::{Child, Command};

use crate::config::{Mode, validate_tag};
use crate::paths::{ensure_private_dir, safe_remove};
use crate::{confine, net};

pub const SWTPM: &str = "/usr/bin/swtpm";
/// swtpm's share of the VM cgroup's memory (it uses about 5 MiB).
pub const MEMORY_MIB: u64 = 32;
/// The TPM state directory, in the VM directory.
pub const DIR: &str = "tpm";
/// swtpm's messages, in the VM directory.
pub const LOG: &str = "swtpm.log";
/// Largest file swtpm may write (`RLIMIT_FSIZE`): its state is tens of
/// KiB, so a guest cannot make it fill the disk.
pub const MAX_FILE_BYTES: libc::rlim_t = 16 << 20;

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
    // SAFETY: runs in the forked child before exec; one setrlimit syscall
    // on a stack value, nothing else.
    #[allow(unsafe_code)]
    unsafe {
        cmd.pre_exec(|| {
            let lim = libc::rlimit {
                rlim_cur: MAX_FILE_BYTES,
                rlim_max: MAX_FILE_BYTES,
            };
            if libc::setrlimit(libc::RLIMIT_FSIZE, &lim) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
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

/// Copies of the TPM state that disk-only snapshots carry, one directory
/// per snapshot: `<vm>/tpm-snapshots/<tag>/`. (A RAM snapshot has the TPM
/// state in its RAM image.) Out of reach of QEMU and swtpm.
const SNAPSHOTS: &str = "tpm-snapshots";

fn copy_dir(vm_dir: &Path, tag: &str) -> PathBuf {
    vm_dir.join(SNAPSHOTS).join(tag)
}

/// swtpm's state files (TPM 2.0); nothing else in `tpm/` is copied.
const STATE_FILES: [&str; 3] = [
    "tpm2-00.permall",
    "tpm2-00.volatilestate",
    "tpm2-00.savestate",
];
/// Where a restore builds the TPM state before swapping it in.
const NEW: &str = "tpm.new";

/// Copies the TPM state for disk-only snapshot `tag` of a stopped VM. The
/// state is a few KiB.
pub fn save_copy(vm_dir: &Path, tag: &str) -> Result<()> {
    validate_tag(tag)?;
    let to = copy_dir(vm_dir, tag);
    safe_remove(vm_dir, &to)?;
    ensure_private_dir(&vm_dir.join(DIR))?;
    ensure_private_dir(&vm_dir.join(SNAPSHOTS))?;
    ensure_private_dir(&to)?;
    copy_files(&vm_dir.join(DIR), &to).context("cannot copy the TPM state")
}

/// Whether disk-only snapshot `tag` has a copy of the TPM state.
pub fn has_copy(vm_dir: &Path, tag: &str) -> bool {
    copy_dir(vm_dir, tag).is_dir()
}

/// First half of restoring snapshot `tag`'s TPM copy into a stopped VM:
/// builds it in `tpm.new/`, beside `tpm/`. Until [`swap_in`] (or
/// [`discard_new`]) the VM does not start.
pub fn prepare_copy(vm_dir: &Path, tag: &str) -> Result<()> {
    validate_tag(tag)?;
    ensure!(
        has_copy(vm_dir, tag),
        "snapshot {tag} has no copy of the TPM state"
    );
    let new = vm_dir.join(NEW);
    safe_remove(vm_dir, &new)?;
    ensure_private_dir(&new)?;
    copy_files(&copy_dir(vm_dir, tag), &new).context("cannot copy the TPM state back")
}

/// Second half: exchanges `tpm.new/` and `tpm/` in one atomic rename, then
/// removes the old state.
pub fn swap_in(vm_dir: &Path) -> Result<()> {
    let (tpm, new) = (vm_dir.join(DIR), vm_dir.join(NEW));
    ensure_private_dir(&tpm)?;
    use rustix::fs::{CWD, RenameFlags, renameat_with};
    renameat_with(CWD, &new, CWD, &tpm, RenameFlags::EXCHANGE)
        .context("cannot swap in the TPM state")?;
    safe_remove(vm_dir, &new)?;
    Ok(())
}

/// Drops a `tpm.new/` that will not be swapped in.
pub fn discard_new(vm_dir: &Path) -> Result<()> {
    safe_remove(vm_dir, &vm_dir.join(NEW))?;
    Ok(())
}

/// Refuses a start while a TPM restore is unfinished.
pub fn check_no_restore_pending(vm_dir: &Path) -> Result<()> {
    ensure!(
        fs::symlink_metadata(vm_dir.join(NEW)).is_err(),
        "a TPM state restore did not finish; restore the snapshot again"
    );
    Ok(())
}

/// Removes the TPM copy of snapshot `tag`, if any.
pub fn remove_copy(vm_dir: &Path, tag: &str) -> Result<()> {
    validate_tag(tag)?;
    safe_remove(vm_dir, &copy_dir(vm_dir, tag))?;
    Ok(())
}

/// Copies swtpm's state files from `from` into the new, empty directory
/// `to`: regular files only (never links) of at most [`MAX_FILE_BYTES`],
/// the most swtpm can write.
fn copy_files(from: &Path, to: &Path) -> Result<()> {
    for name in STATE_FILES {
        let path = from.join(name);
        match fs::symlink_metadata(&path) {
            Ok(m) if m.is_file() && m.len() <= MAX_FILE_BYTES => {
                fs::copy(&path, to.join(name))?;
            }
            Ok(_) => tracing::warn!("{}: not copied (not a small file)", path.display()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
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

    /// A disk-only snapshot's TPM copy goes back exactly: state files
    /// added since are gone; links, the lock, other and oversized files are
    /// never copied.
    #[test]
    fn snapshot_copies() {
        let tmp = tempfile::tempdir().unwrap();
        let vm = std::fs::canonicalize(tmp.path()).unwrap();
        let tpm = vm.join(DIR);
        crate::paths::ensure_private_dir(&tpm).unwrap();
        fs::write(tpm.join("tpm2-00.permall"), b"old").unwrap();
        fs::write(tpm.join(".lock"), b"").unwrap();
        fs::write(tpm.join("other"), b"x").unwrap();
        fs::File::create(tpm.join("tpm2-00.savestate"))
            .unwrap()
            .set_len(MAX_FILE_BYTES + 1)
            .unwrap();
        std::os::unix::fs::symlink("/etc/passwd", tpm.join("tpm2-00.volatilestate")).unwrap();
        assert!(!has_copy(&vm, "s1"));
        save_copy(&vm, "s1").unwrap();
        assert!(has_copy(&vm, "s1"));
        let names = |d: &Path| {
            let mut n: Vec<_> = fs::read_dir(d)
                .unwrap()
                .map(|e| e.unwrap().file_name().into_string().unwrap())
                .collect();
            n.sort();
            n
        };
        assert_eq!(names(&vm.join("tpm-snapshots/s1")), ["tpm2-00.permall"]);

        fs::write(tpm.join("tpm2-00.permall"), b"new").unwrap();
        prepare_copy(&vm, "s1").unwrap();
        // Nothing changed yet, and the VM may not start.
        assert_eq!(fs::read(tpm.join("tpm2-00.permall")).unwrap(), b"new");
        assert!(check_no_restore_pending(&vm).is_err());
        swap_in(&vm).unwrap();
        check_no_restore_pending(&vm).unwrap();
        assert_eq!(names(&tpm), ["tpm2-00.permall"]);
        assert_eq!(fs::read(tpm.join("tpm2-00.permall")).unwrap(), b"old");
        // A prepared restore can be dropped instead.
        prepare_copy(&vm, "s1").unwrap();
        discard_new(&vm).unwrap();
        check_no_restore_pending(&vm).unwrap();
        // The copy stays for the next restore, until the snapshot goes.
        assert!(has_copy(&vm, "s1"));
        remove_copy(&vm, "s1").unwrap();
        assert!(!has_copy(&vm, "s1"));
        assert!(prepare_copy(&vm, "s1").is_err());
        assert_eq!(fs::read(tpm.join("tpm2-00.permall")).unwrap(), b"old");
        assert!(save_copy(&vm, "../x").is_err());
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
