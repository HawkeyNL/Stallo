//! Confinement for QEMU (and swtpm, see [`swtpm_rules`]), applied without
//! root: Landlock plus a small seccomp filter.
//!
//! QEMU runs under the daemon's UID, so without confinement a guest that
//! escapes into QEMU could read and write everything that UID can: other
//! VMs' disks, the daemon's data, cgroup control files, the user's home.
//! Before `exec`, each QEMU child restricts itself with a Landlock ruleset
//! built from [`qemu_rules`]:
//!
//! - its own disk, firmware variables, snapshot state and seed, and the
//!   read-only base image;
//! - its own runtime directory (QMP and QGA sockets);
//! - the read-only system files QEMU loads (`/usr`, `ld.so.cache`, a few
//!   `/sys` and `/proc/sys` entries) and the device nodes it uses;
//! - no TCP bind or connect, no signals or abstract Unix sockets outside
//!   the sandbox.
//!
//! Everything else on the filesystem is denied, including other VMs and
//! `/sys/fs/cgroup`. The ruleset is built in the daemon (allocation is not
//! allowed after `fork`) and only enforced in `pre_exec`.
//!
//! Landlock before ABI 9 (Linux 7.1) cannot stop `connect()` to a pathname
//! Unix socket, so QEMU could still reach the daemon's API socket, other
//! VMs' QMP sockets or the user's D-Bus. The seccomp filter closes that:
//! no `connect`, sockets only of type `AF_UNIX`/`SOCK_STREAM` (QEMU only
//! listens), and no `io_uring_setup` (io_uring operations bypass seccomp;
//! QEMU falls back to `ppoll`).
//!
//! Fail closed: if the kernel lacks Landlock ABI 6 (Linux 6.12), a VM does not
//! start. Newer Landlock rights (ABI 9) are used when the kernel has them.

use std::io;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use landlock::{
    ABI, Access, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, PathBeneath, PathFd,
    Ruleset, RulesetAttr, RulesetCreated, RulesetCreatedAttr, RulesetStatus, Scope,
};
use libc::{sock_filter, sock_fprog};
use tokio::process::Command;

/// What must be enforced in full, or QEMU does not start: all filesystem
/// rights up to truncate and device ioctls, TCP, and scoping of signals and
/// abstract Unix sockets.
const REQUIRED: ABI = ABI::V6;
/// Enforced when the running kernel has it.
const WANTED: ABI = ABI::V9;

/// One rule: `access` to `path` and, for a directory, everything below it.
pub type Rule = (PathBuf, BitFlags<AccessFs>);

/// The rules for one VM's QEMU. `backing` are the read-only files it
/// reads besides its own: the base image below its disk, for a `stallo run`
/// clone the source VM's disk, and an installer ISO in its CD-ROM drive.
/// All paths must exist when the ruleset is built; the seed is covered only
/// if the VM has one (VMs from ISOs do not).
pub fn qemu_rules(
    vm_dir: &Path,
    rt_dir: &Path,
    vnc_dir: Option<&Path>,
    backing: &[PathBuf],
) -> Vec<Rule> {
    use AccessFs::*;
    let read = ReadFile | ReadDir;
    let rw_file = ReadFile | WriteFile;
    // qcow2 may shrink its files (snapshot delete, discard).
    let disk = rw_file | Truncate;
    [
        // The binary, its libraries, firmware and option ROMs. /etc/localtime
        // links into /usr/share/zoneinfo.
        ("/usr".into(), read | Execute),
        ("/etc/ld.so.cache".into(), ReadFile.into()),
        // Host CPU and NUMA topology, memory overcommit settings.
        ("/sys/devices/system/cpu".into(), read),
        ("/sys/devices/system/node".into(), read),
        ("/proc/sys/vm".into(), read),
        ("/dev/kvm".into(), rw_file | IoctlDev),
        ("/dev/null".into(), rw_file),
        ("/dev/urandom".into(), ReadFile.into()),
        (vm_dir.join(crate::qemu::DISK), disk),
        (vm_dir.join(crate::qemu::VARS), disk),
        // The images of RAM snapshots: the daemon creates them; QEMU may
        // read and write them, never create, link or remove files there.
        // (It is asked to open one only during a snapshot job.)
        (vm_dir.join(crate::qemu::STATES), disk),
        // QEMU removes a stale socket and creates a new one at start, and
        // removes it again at exit.
        (rt_dir.into(), MakeSock | RemoveFile),
    ]
    .into_iter()
    .chain(
        Some(vm_dir.join(crate::qemu::SEED))
            .filter(|seed| seed.exists())
            .map(|seed| (seed, ReadFile.into())),
    )
    // The VNC socket, like the others (`stallo set <vm> --vnc on`).
    .chain(vnc_dir.map(|d| (d.into(), MakeSock | RemoveFile)))
    .chain(backing.iter().map(|b| (b.clone(), ReadFile.into())))
    // Screendumps overwrite files the daemon created (no new files).
    .chain(
        crate::qemu::SCREEN_FILES
            .iter()
            .map(|f| (rt_dir.join(f), WriteFile | Truncate)),
    )
    .collect()
}

/// The rules for a Windows VM's swtpm (`crate::tpm`): the system files it
/// loads and its own TPM state directory `tpm_dir`, where it writes a
/// temporary file, renames it over the state file and keeps a `.lock`
/// file. No directory listing, links, sockets or devices besides
/// `/dev/urandom`. swtpm parses guest-controlled TPM commands (libtpms), so
/// it gets nothing else: not the VM's disk, not another VM's TPM.
pub fn swtpm_rules(tpm_dir: &Path) -> Vec<Rule> {
    use AccessFs::*;
    vec![
        ("/usr".into(), ReadFile | ReadDir | Execute),
        ("/etc/ld.so.cache".into(), ReadFile.into()),
        ("/dev/urandom".into(), ReadFile.into()),
        (
            tpm_dir.into(),
            ReadFile | WriteFile | Truncate | MakeReg | RemoveFile,
        ),
    ]
}

/// The rules for `qemu-img` on a VM's own files, which a compromised QEMU
/// may have crafted: the system files it loads, and read-write access to
/// `files` only.
pub fn tool_rules(files: &[PathBuf]) -> Vec<Rule> {
    use AccessFs::*;
    [
        ("/usr".into(), ReadFile | ReadDir | Execute),
        ("/etc/ld.so.cache".into(), ReadFile.into()),
        ("/dev/null".into(), ReadFile | WriteFile),
    ]
    .into_iter()
    .chain(
        files
            .iter()
            .map(|f| (f.clone(), ReadFile | WriteFile | Truncate)),
    )
    .collect()
}

/// Builds the ruleset in the daemon, so the child only has to enforce it.
pub fn build(rules: &[Rule]) -> Result<RulesetCreated> {
    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(REQUIRED))
        .and_then(|r| r.handle_access(AccessNet::from_all(REQUIRED)))
        .and_then(|r| r.scope(Scope::from_all(REQUIRED)))
        .map(|r| r.set_compatibility(CompatLevel::BestEffort))
        .and_then(|r| r.handle_access(AccessFs::from_all(WANTED)))
        .and_then(Ruleset::create)
        // Denials of the exec'd QEMU go to the kernel audit log (ABI 7).
        .and_then(|r| r.log_new_exec(true))
        .with_context(|| {
            format!(
                "cannot confine with Landlock (needs Landlock ABI {} / Linux 6.12 or newer)",
                REQUIRED as u32
            )
        })?
        // A rule that cannot be added as written is a bug: fail.
        .set_compatibility(CompatLevel::HardRequirement);
    for (path, access) in rules {
        let fd =
            PathFd::new(path).with_context(|| format!("cannot confine: {}", path.display()))?;
        ruleset = ruleset
            .add_rule(PathBeneath::new(fd, *access))
            .with_context(|| format!("cannot confine: rule for {}", path.display()))?;
    }
    Ok(ruleset)
}

#[cfg(not(target_arch = "x86_64"))]
compile_error!("the QEMU seccomp filter is written for x86_64");

const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
const X32_SYSCALL_BIT: u32 = 0x4000_0000;
const SOCK_TYPE_MASK: u32 = 0xf;
/// Linux 6.13 syscalls that the libc crate does not name yet.
const SETXATTRAT: libc::c_long = 463;
const REMOVEXATTRAT: libc::c_long = 466;

/// Syscalls QEMU never needs that reach beyond Landlock: file modes and
/// owners (other VMs' disks, the API socket, cgroup files), extended
/// attributes, other processes' I/O priority, and the user's keyrings.
const DENIED: [libc::c_long; 20] = {
    use libc::*;
    [
        SYS_chmod,
        SYS_fchmod,
        SYS_fchmodat,
        SYS_fchmodat2,
        SYS_chown,
        SYS_fchown,
        SYS_lchown,
        SYS_fchownat,
        SYS_setxattr,
        SYS_lsetxattr,
        SYS_fsetxattr,
        SETXATTRAT,
        SYS_removexattr,
        SYS_lremovexattr,
        SYS_fremovexattr,
        REMOVEXATTRAT,
        SYS_ioprio_set,
        SYS_add_key,
        SYS_request_key,
        SYS_keyctl,
    ]
};

/// Appends a conditional jump to the absolute instruction `hit` when the
/// comparison holds, to `miss` otherwise (BPF jumps are relative and
/// forward only).
fn jump(f: &mut Vec<sock_filter>, code: u32, k: u32, hit: usize, miss: usize) {
    let next = f.len() + 1;
    f.push(sock_filter {
        code: code as u16,
        jt: u8::try_from(hit - next).expect("short forward jump"),
        jf: u8::try_from(miss - next).expect("short forward jump"),
        k,
    });
}

/// The seccomp program, built in the daemon (it allocates). Offsets into
/// `struct seccomp_data`: `nr` at 0, `arch` at 4, `args[i]` at `16 + 8 * i`
/// (low half on little endian). Every decision jumps forward to one of the
/// returns at the end.
fn filter() -> Vec<sock_filter> {
    use libc::*;
    const LD: u32 = BPF_LD | BPF_W | BPF_ABS;
    const JEQ: u32 = BPF_JMP | BPF_JEQ | BPF_K;
    const RET: u32 = BPF_RET | BPF_K;
    let stmt = |code: u32, k: u32| sock_filter {
        code: code as u16,
        jt: 0,
        jf: 0,
        k,
    };
    // Layout: 4 header, one check per syscall rule, then the socket and
    // prlimit argument checks, then the returns.
    let checks = 6 + DENIED.len();
    let socket_check = 4 + checks;
    let prlimit_check = socket_check + 5;
    let allow = prlimit_check + 2;
    let (enosys, eacces, eafnosupport, eperm) = (allow + 1, allow + 2, allow + 3, allow + 4);

    let mut f = Vec::with_capacity(eperm + 1);
    f.push(stmt(LD, 4));
    jump(&mut f, JEQ, AUDIT_ARCH_X86_64, 3, 2);
    f.push(stmt(RET, SECCOMP_RET_KILL_PROCESS));
    f.push(stmt(LD, 0));
    jump(
        &mut f,
        BPF_JMP | BPF_JGE | BPF_K,
        X32_SYSCALL_BIT,
        enosys,
        5,
    );
    let rules: Vec<(c_long, usize)> = [
        (SYS_io_uring_setup, enosys),
        (SYS_connect, eacces),
        (SYS_socket, socket_check),
        (SYS_socketpair, socket_check),
        (SYS_prlimit64, prlimit_check),
    ]
    .into_iter()
    .chain(DENIED.iter().map(|&nr| (nr, eperm)))
    .collect();
    for (i, (nr, target)) in rules.iter().enumerate() {
        // No match: the next check, or `allow` after the last one.
        let miss = if i + 1 == rules.len() {
            allow
        } else {
            f.len() + 1
        };
        jump(&mut f, JEQ, *nr as u32, *target, miss);
    }
    // socket(2) and socketpair(2): only AF_UNIX stream sockets.
    debug_assert_eq!(f.len(), socket_check);
    f.push(stmt(LD, 16));
    jump(&mut f, JEQ, AF_UNIX as u32, socket_check + 2, eafnosupport);
    f.push(stmt(LD, 24));
    f.push(stmt(BPF_ALU | BPF_AND | BPF_K, SOCK_TYPE_MASK));
    jump(&mut f, JEQ, SOCK_STREAM as u32, allow, eafnosupport);
    // prlimit64(2): only on itself (pid 0, as glibc's setrlimit calls it).
    debug_assert_eq!(f.len(), prlimit_check);
    f.push(stmt(LD, 16));
    jump(&mut f, JEQ, 0, allow, eperm);
    debug_assert_eq!(f.len(), allow);
    f.push(stmt(RET, SECCOMP_RET_ALLOW));
    for e in [ENOSYS, EACCES, EAFNOSUPPORT, EPERM] {
        f.push(stmt(RET, SECCOMP_RET_ERRNO | e as u32));
    }
    f
}

/// The AppArmor profile of QEMU in production mode
/// (`packaging/apparmor/stallo-qemu`).
pub const QEMU_PROFILE: &str = "stallo-qemu";
/// The AppArmor profile of swtpm in production mode
/// (`packaging/apparmor/stallo-swtpm`).
pub const SWTPM_PROFILE: &str = "stallo-swtpm";

/// Makes `cmd` enter AppArmor profile `profile` at `exec` (what
/// libapparmor's `aa_change_onexec` does). The spawn fails if the profile
/// is not loaded. Register it before [`confine_on_exec`], whose Landlock
/// ruleset denies `/proc`.
pub fn apparmor_on_exec(cmd: &mut Command, profile: &str) {
    // Built before the fork: the child may not allocate.
    let line = format!("exec {profile}").into_bytes();
    // SAFETY: the closure runs in the forked child before exec. It only makes
    // raw syscalls through rustix (open, write, close) on data built before
    // the fork, with no allocation, locking or logging.
    #[allow(unsafe_code)]
    unsafe {
        cmd.pre_exec(move || {
            let attr = rustix::fs::open(
                c"/proc/self/attr/apparmor/exec",
                rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )?;
            if rustix::io::write(&attr, &line)? != line.len() {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            Ok(())
        });
    }
}

/// Checks that process `pid` runs under the enforced AppArmor profile
/// `profile`; anything else is an error (fail closed).
pub fn check_profile(pid: u32, profile: &str) -> Result<()> {
    let label = std::fs::read_to_string(format!("/proc/{pid}/attr/apparmor/current"))
        .with_context(|| format!("cannot read the AppArmor label of process {pid}"))?;
    let label = label.trim_end();
    ensure!(
        is_label(label, profile),
        "process {pid} runs as {label:?}, not under the AppArmor profile {profile} in enforce mode"
    );
    Ok(())
}

/// An unprivileged, unconfined process that changes profile gets the
/// profile stacked on `unconfined` (lab, Ubuntu 26.04); the intersection
/// is the profile itself.
fn is_label(label: &str, profile: &str) -> bool {
    label
        .strip_suffix(" (enforce)")
        .and_then(|l| l.strip_prefix(profile))
        .is_some_and(|rest| rest.is_empty() || rest == "//&unconfined")
}

/// Makes `cmd` confine itself right before `exec`: first the Landlock
/// `ruleset` (which also sets `no_new_privs`), then the seccomp filter.
/// Register it after every other `pre_exec` hook: those still open files
/// (cgroup, `oom_score_adj`) that the ruleset denies.
pub fn confine_on_exec(cmd: &mut Command, ruleset: RulesetCreated) {
    let mut ruleset = Some(ruleset);
    let program = filter();
    // SAFETY: the closure runs in the forked child before exec. `take` moves
    // a value out of the closure's own state; `restrict_self` makes two
    // syscalls (prctl(PR_SET_NO_NEW_PRIVS) and landlock_restrict_self) and
    // closes the ruleset fd; `prctl(PR_SET_SECCOMP)` reads the program built
    // before the fork. No allocation, locking or logging.
    #[allow(unsafe_code)]
    unsafe {
        cmd.pre_exec(move || {
            let denied = || io::Error::from_raw_os_error(libc::EPERM);
            let ruleset = ruleset.take().ok_or_else(denied)?;
            match ruleset.restrict_self() {
                Ok(s) if s.ruleset != RulesetStatus::NotEnforced && s.no_new_privs => {}
                _ => return Err(denied()),
            }
            let prog = sock_fprog {
                len: program.len() as u16,
                filter: program.as_ptr().cast_mut(),
            };
            if libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER as libc::c_ulong,
                &prog as *const sock_fprog,
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// The running kernel's Landlock ABI (0 without Landlock).
#[cfg(test)]
pub(crate) fn kernel_abi() -> i64 {
    // SAFETY: LANDLOCK_CREATE_RULESET_VERSION with a null attribute only
    // returns a number.
    #[allow(unsafe_code)]
    let v = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<u8>(),
            0,
            1,
        )
    };
    v.max(0)
}

/// Whether confinement works here; tests that need it skip otherwise.
#[cfg(test)]
pub(crate) fn available() -> bool {
    let ok = kernel_abi() >= REQUIRED as i64;
    if !ok {
        eprintln!(
            "skipped: kernel Landlock ABI {} < {}",
            kernel_abi(),
            REQUIRED as u32
        );
    }
    ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn rules_cover_only_this_vm() {
        let rules = qemu_rules(
            Path::new("/d/vms/dev"),
            Path::new("/r/vms/dev"),
            None,
            &["/d/images/ubuntu-26.04.qcow2".into()],
        );
        let paths: Vec<&str> = rules.iter().map(|(p, _)| p.to_str().unwrap()).collect();
        for p in &paths {
            assert!(
                !p.starts_with("/d/")
                    || p.starts_with("/d/vms/dev/")
                    || p.starts_with("/d/images/"),
                "{p}"
            );
            assert!(
                !p.starts_with("/sys/fs") && *p != "/" && *p != "/etc" && *p != "/proc",
                "{p}"
            );
        }
        // VNC adds its own socket directory, nothing else.
        let with_vnc = qemu_rules(
            Path::new("/d/vms/dev"),
            Path::new("/r/vms/dev"),
            Some(Path::new("/r/vnc/dev")),
            &["/d/images/ubuntu-26.04.qcow2".into()],
        );
        let extra: Vec<_> = with_vnc.iter().filter(|r| !rules.contains(r)).collect();
        assert_eq!(
            extra,
            [&(
                PathBuf::from("/r/vnc/dev"),
                AccessFs::MakeSock | AccessFs::RemoveFile
            )]
        );
        // The VM directory itself is not granted (vm.toml, secret, logs), only
        // its disk files; nothing may execute outside /usr.
        assert!(!paths.contains(&"/d/vms/dev"));
        for (p, access) in &rules {
            if access.contains(AccessFs::Execute) {
                assert_eq!(p, Path::new("/usr"));
            }
        }
    }

    #[test]
    fn profile_labels() {
        assert!(is_label("stallo-qemu (enforce)", QEMU_PROFILE));
        assert!(is_label("stallo-qemu//&unconfined (enforce)", QEMU_PROFILE));
        assert!(is_label("stallo-swtpm (enforce)", SWTPM_PROFILE));
        assert!(is_label(
            "stallo-swtpm//&unconfined (enforce)",
            SWTPM_PROFILE
        ));
        // The distro's own swtpm profile is not ours.
        assert!(!is_label("swtpm (enforce)", SWTPM_PROFILE));
        assert!(!is_label("stallo-qemu (enforce)", SWTPM_PROFILE));
        assert!(!is_label("stallo-swtpm (enforce)", QEMU_PROFILE));
        for bad in [
            "unconfined",
            "stallo-qemu (complain)",
            "stallo-qemu//&unconfined (complain)",
            "stallo-qemu//&other (enforce)",
            "stallo-qemu-x (enforce)",
            "other (enforce)",
            "",
        ] {
            assert!(!is_label(bad, QEMU_PROFILE), "{bad}");
        }
    }

    /// Runs `sh -c script` confined to `rules`; returns whether it succeeded,
    /// or `None` (skipped) if the kernel lacks the required Landlock ABI.
    fn confined(rules: &[Rule], script: &str) -> Option<bool> {
        if !available() {
            return None;
        }
        let mut cmd = Command::new("/usr/bin/sh");
        cmd.args(["-c", script]);
        confine_on_exec(&mut cmd, build(rules).unwrap());
        let status = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async { cmd.status().await.unwrap() });
        Some(status.success())
    }

    #[test]
    fn filter_jumps_stay_inside_the_program() {
        let f = filter();
        assert!(f.len() < 64, "{}", f.len());
        for (i, ins) in f.iter().enumerate() {
            if ins.code as u32 & 0x07 == libc::BPF_JMP {
                assert!(i + 1 + (ins.jt.max(ins.jf) as usize) < f.len(), "{i}");
            }
        }
        // Ends in returns only: allow, then the four errors.
        let rets = f.iter().rev().take(5);
        assert!(
            rets.into_iter()
                .all(|i| i.code as u32 == libc::BPF_RET | libc::BPF_K)
        );
    }

    #[test]
    fn other_vms_and_cgroups_are_denied() {
        let tmp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(tmp.path()).unwrap();
        let (own, other, rt, img) = (
            root.join("vms/dev"),
            root.join("vms/other"),
            root.join("run/dev"),
            root.join("base.qcow2"),
        );
        for d in [&own, &other, &rt] {
            fs::create_dir_all(d).unwrap();
        }
        vm_files(&own, b"x");
        vm_files(&other, b"x");
        fs::write(&img, b"base").unwrap();
        fs::write(own.join("secret"), b"pw").unwrap();
        screen_files(&rt);
        let rules = qemu_rules(&own, &rt, None, std::slice::from_ref(&img));
        let q = |p: &Path| format!("'{}'", p.display());
        let disk = |d: &Path| q(&d.join(crate::qemu::DISK));

        let Some(ok) = confined(
            &rules,
            &format!("cat {} {} >/dev/null", disk(&own), q(&img)),
        ) else {
            return;
        };
        assert!(ok, "own disk and base image must be readable");
        assert_eq!(
            confined(&rules, &format!("echo y >> {}", disk(&own))),
            Some(true)
        );
        // Its RAM snapshot images: read and write, never create or swap.
        let states = |d: &Path| d.join(crate::qemu::STATES);
        let own_state = q(&states(&own).join("s1.qcow2"));
        assert_eq!(
            confined(&rules, &format!("cat {own_state} && echo y >> {own_state}")),
            Some(true)
        );
        for denied in [
            format!("touch {}", q(&states(&own).join("new.qcow2"))),
            format!("ln -s /etc/passwd {}", q(&states(&own).join("l.qcow2"))),
            format!("rm {own_state}"),
            format!("mv {own_state} {}", q(&states(&own).join("s2.qcow2"))),
            format!("ln {own_state} {}", q(&states(&own).join("h.qcow2"))),
            format!("cat {}", q(&states(&other).join("s1.qcow2"))),
        ] {
            assert_eq!(confined(&rules, &denied), Some(false), "{denied}");
        }
        let screen = q(&rt.join("screen.png"));
        assert_eq!(
            confined(&rules, &format!("echo png > {screen}")),
            Some(true)
        );
        for denied in [
            format!("cat {}", disk(&other)),
            format!("echo y >> {}", disk(&other)),
            format!("echo y >> {}", q(&img)),
            format!("cat {}", q(&own.join("secret"))),
            format!("chmod 666 {}", disk(&other)),
            format!("chmod 666 {}", q(&rt)),
            format!("echo x > {}", q(&rt.join("other.png"))),
            format!("cat {screen}"),
            format!("touch {}", q(&own.join("new"))),
            format!("ls {}", q(&root)),
            "cat /sys/fs/cgroup/cgroup.controllers".to_owned(),
            "cat /proc/self/environ".to_owned(),
            "ls /home /etc".to_owned(),
        ] {
            assert_eq!(confined(&rules, &denied), Some(false), "{denied}");
        }
        assert_eq!(fs::read(other.join(crate::qemu::DISK)).unwrap(), b"x");

        // A `stallo run` clone of `other` reads its disk, nothing more.
        let clone = qemu_rules(
            &own,
            &rt,
            None,
            &[img.clone(), other.join(crate::qemu::DISK)],
        );
        assert_eq!(
            confined(&clone, &format!("cat {}", disk(&other))),
            Some(true)
        );
        for denied in [
            format!("echo y >> {}", disk(&other)),
            format!("cat {}", q(&other.join(crate::qemu::VARS))),
        ] {
            assert_eq!(confined(&clone, &denied), Some(false), "{denied}");
        }

        // QEMU may delete its screen files but never put a link, FIFO or
        // new file in their place.
        for swap in ["ln -s /etc/passwd", "mkfifo", "touch"] {
            screen_files(&rt);
            let script = format!("rm {screen} && {swap} {screen}");
            assert_eq!(confined(&rules, &script), Some(false), "{script}");
            assert!(!rt.join("screen.png").exists(), "{script}");
        }

        // A VM from an ISO has no seed and reads its ISO, never writes it.
        let iso = root.join("x.iso");
        fs::write(&iso, b"iso").unwrap();
        fs::remove_file(own.join(crate::qemu::SEED)).unwrap();
        screen_files(&rt);
        let iso_rules = qemu_rules(&own, &rt, None, std::slice::from_ref(&iso));
        assert!(
            !iso_rules
                .iter()
                .any(|(p, _)| p.ends_with(crate::qemu::SEED))
        );
        assert_eq!(
            confined(&iso_rules, &format!("cat {}", q(&iso))),
            Some(true)
        );
        for denied in [
            format!("echo y >> {}", q(&iso)),
            format!("cat {}", q(&img)),
            format!("touch {}", q(&own.join(crate::qemu::SEED))),
        ] {
            assert_eq!(confined(&iso_rules, &denied), Some(false), "{denied}");
        }
    }

    /// swtpm reaches its own TPM state and nothing else of any VM.
    #[test]
    fn swtpm_sees_only_its_tpm_dir() {
        let rules = swtpm_rules(Path::new("/d/vms/win/tpm"));
        for (p, access) in &rules {
            let p = p.to_str().unwrap();
            assert!(!p.starts_with("/d/") || p == "/d/vms/win/tpm", "{p}");
            assert!(!access.contains(AccessFs::Execute) || p == "/usr", "{p}");
            assert!(!access.contains(AccessFs::MakeSym) && !access.contains(AccessFs::Refer));
        }

        let tmp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(tmp.path()).unwrap();
        let (own, other) = (root.join("vms/win"), root.join("vms/other"));
        for d in [&own, &other] {
            fs::create_dir_all(d.join("tpm")).unwrap();
            vm_files(d, b"x");
            fs::write(d.join("tpm/tpm2-00.permall"), b"state\n").unwrap();
        }
        let rules = swtpm_rules(&own.join("tpm"));
        let q = |p: &Path| format!("'{}'", p.display());
        let (tpm, state) = (q(&own.join("tpm")), q(&own.join("tpm/tpm2-00.permall")));
        // What swtpm does: read, write a temporary file and rename it over
        // the state, lock and remove files.
        let Some(ok) = confined(
            &rules,
            &format!(
                "read -r x < {state} && echo new > {tpm}/TMP2-00.permall && \
                 mv {tpm}/TMP2-00.permall {state} && : > {tpm}/.lock && rm {tpm}/.lock"
            ),
        ) else {
            return;
        };
        assert!(ok, "swtpm's own state must be usable");
        assert_eq!(fs::read(own.join("tpm/tpm2-00.permall")).unwrap(), b"new\n");
        for denied in [
            format!("cat {}", q(&other.join("tpm/tpm2-00.permall"))),
            format!("echo y > {}", q(&other.join("tpm/tpm2-00.permall"))),
            format!("cat {}", q(&own.join(crate::qemu::DISK))),
            format!("touch {}", q(&own.join("new"))),
            format!("ls {tpm}"),
            format!("ln -s /etc/passwd {tpm}/link"),
            format!("mkdir {tpm}/sub"),
            format!("chmod 666 {state}"),
            "cat /proc/self/environ".to_owned(),
        ] {
            assert_eq!(confined(&rules, &denied), Some(false), "{denied}");
        }
        assert_eq!(
            fs::read(other.join("tpm/tpm2-00.permall")).unwrap(),
            b"state\n"
        );
    }

    /// The seccomp part: no `connect`, no sockets but Unix streams, no
    /// io_uring. Probed with python3, which the confined process may run.
    #[test]
    fn sockets_and_io_uring_are_denied() {
        let tmp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(tmp.path()).unwrap();
        let (vm, rt) = (root.join("vm"), root.join("rt"));
        for d in [&vm, &rt] {
            fs::create_dir(d).unwrap();
        }
        vm_files(&vm, b"");
        fs::write(root.join("img"), b"").unwrap();
        screen_files(&rt);
        // Stands in for the daemon's API socket or another VM's QMP socket.
        let api = root.join("api.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&api).unwrap();
        let script = format!(
            r#"python3 -c '
import socket, ctypes, os, resource
def fails(f):
    try:
        f()
    except OSError:
        return True
    return False
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
assert fails(lambda: s.connect("{api}")), "connect"
assert fails(lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM)), "inet"
assert fails(lambda: socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)), "inet6"
assert fails(lambda: socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)), "dgram"
assert fails(lambda: socket.socket(socket.AF_NETLINK, socket.SOCK_RAW)), "netlink"
assert fails(lambda: socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)), "socketpair"
assert fails(lambda: os.chmod("{api}", 0o666)), "chmod"
assert fails(lambda: resource.prlimit(os.getppid(), resource.RLIMIT_NOFILE)), "prlimit"
resource.prlimit(0, resource.RLIMIT_NOFILE)
socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind("{rt}/qmp.sock")
s.listen()
libc = ctypes.CDLL(None, use_errno=True)
assert libc.syscall(425, 1, ctypes.create_string_buffer(120)) == -1, "io_uring"
assert ctypes.get_errno() == 38
assert libc.syscall(250, 0, 0) == -1 and ctypes.get_errno() == 1, "keyctl"
'"#,
            api = api.display(),
            rt = rt.display()
        );
        let rules = qemu_rules(&vm, &rt, None, &[root.join("img")]);
        if let Some(ok) = confined(&rules, &script) {
            assert!(ok, "a socket, connect or io_uring was allowed");
        }
        // The same script fails unconfined (connect works), so the probe
        // itself is sound.
        let free = std::process::Command::new("sh")
            .args([
                "-c",
                &script.replace(&rt.display().to_string(), &root.display().to_string()),
            ])
            .output()
            .unwrap();
        assert!(!free.status.success());
        assert!(String::from_utf8_lossy(&free.stderr).contains("connect"));
    }

    fn screen_files(rt: &Path) {
        for f in crate::qemu::SCREEN_FILES {
            fs::write(rt.join(f), b"").unwrap();
        }
    }

    /// A VM's files with `content`, and its RAM snapshot directory with
    /// one image.
    fn vm_files(dir: &Path, content: &[u8]) {
        use crate::qemu::{DISK, SEED, STATES, VARS};
        for f in [DISK, VARS, SEED] {
            fs::write(dir.join(f), content).unwrap();
        }
        fs::create_dir(dir.join(STATES)).unwrap();
        fs::write(dir.join(STATES).join("s1.qcow2"), content).unwrap();
    }
}
