//! cgroup v2 handling inside the daemon's delegated subtree.
//!
//! systemd delegates the daemon's own cgroup (`Delegate=yes`). The daemon
//! moves itself into a `daemon/` leaf (cgroup v2 allows controllers only on
//! cgroups without processes of their own), enables `cpu memory pids` for
//! its children, and gives every VM a `vm-<name>/` sibling with hard limits.
//!
//! ```text
//! <delegated>/                cgroup.subtree_control = +cpu +memory +pids
//! <delegated>/daemon/         stallod itself
//! <delegated>/tools/          helper programs (curl, gpgv, qemu-img, ...), memory.max = 1G
//! <delegated>/vm-<name>/      one QEMU process and its limits
//! ```
//!
//! Callers serialise lifecycle operations per VM (`vm.rs` holds a per-name
//! lock), so creating, spawning into and removing one `vm-<name>` never race.
//!
//! QEMU runs under the daemon's UID; Landlock (`confine.rs`) keeps it away
//! from these control files.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::process::Command;

const CONTROLLERS: [&str; 3] = ["cpu", "memory", "pids"];
const DAEMON_LEAF: &str = "daemon";
const TOOLS_LEAF: &str = "tools";
/// Caps all helper programs together; kept apart from the daemon so their
/// page cache never throttles it.
const TOOLS_MEMORY_MAX: &str = "1G";
/// `cpu.max` is `vcpus` CPUs: QEMU's I/O threads share that budget, so a
/// guest that saturates every vCPU slows its own I/O, never the host.
const CPU_PERIOD_US: u64 = 100_000;
/// Linux guests stay far below this; it stops fork bombs inside QEMU.
const PIDS_MAX: u32 = 512;
/// Picked by the kernel OOM killer before host services (default 0).
const OOM_SCORE_ADJ: &[u8] = b"500";

/// Hard limits for one VM cgroup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub memory_max_bytes: u64,
    pub vcpus: u32,
}

/// The `tools` leaf, set once by `Cgroups::setup`. A global so `run_tool`
/// can use it without every caller passing it along.
static TOOLS: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// The daemon's delegated cgroup.
#[derive(Debug, Clone)]
pub struct Cgroups {
    root: PathBuf,
}

impl Cgroups {
    /// Finds the daemon's cgroup, checks that it is delegated and sets it up.
    /// Fails closed: without working limits the daemon does not start.
    pub fn setup() -> Result<Self> {
        let own = fs::read_to_string("/proc/self/cgroup")?;
        let rel = parse_own_cgroup(&own)?;
        let root = Path::new("/sys/fs/cgroup").join(rel.trim_start_matches('/'));
        let cg = Self::setup_at(root, std::process::id()).context("cgroup delegation is missing; start stallod with `systemd-run --user -p Delegate=yes` (dev) or from stallod.service")?;
        let _ = TOOLS.set(cg.root.join(TOOLS_LEAF));
        Ok(cg)
    }

    fn setup_at(root: PathBuf, pid: u32) -> Result<Self> {
        let controllers = fs::read_to_string(root.join("cgroup.controllers"))?;
        let have: Vec<&str> = controllers.split_whitespace().collect();
        if let Some(missing) = CONTROLLERS.iter().find(|c| !have.contains(c)) {
            bail!(
                "controller {missing} is not delegated to {}",
                root.display()
            );
        }
        let leaf = root.join(DAEMON_LEAF);
        create_dir(&leaf)?;
        write(&leaf.join("cgroup.procs"), pid.to_string().as_bytes())?;
        write(&root.join("cgroup.subtree_control"), b"+cpu +memory +pids")?;
        let tools = root.join(TOOLS_LEAF);
        create_dir(&tools)?;
        write(&tools.join("memory.max"), TOOLS_MEMORY_MAX.as_bytes())?;
        Ok(Self { root })
    }

    pub fn vm_dir(&self, name: &str) -> PathBuf {
        self.root.join(format!("vm-{name}"))
    }

    /// Creates `vm-<name>` with its limits. A leftover cgroup of the same
    /// name is killed and removed first.
    pub async fn create_vm(&self, name: &str, limits: Limits) -> Result<PathBuf> {
        let dir = self.vm_dir(name);
        kill_and_remove(&dir).await?;
        // Not create_dir: an existing directory now means a concurrent
        // creator, which must not be reused.
        fs::create_dir(&dir).with_context(|| format!("cannot create {}", dir.display()))?;
        for (file, value) in limit_files(limits) {
            write(&dir.join(file), value.as_bytes())?;
        }
        Ok(dir)
    }

    /// `memory.max - (memory.current - file)` of `vm-<name>`: memory the VM
    /// may still take. Page cache (`file`, e.g. snapshot RAM images) is left
    /// out: the host counts it as available too, and it can be reclaimed.
    /// 0 if unknown.
    pub fn unused_memory_bytes(&self, name: &str) -> u64 {
        let dir = self.vm_dir(name);
        let read =
            |f: &str| -> Option<u64> { fs::read_to_string(dir.join(f)).ok()?.trim().parse().ok() };
        let file = fs::read_to_string(dir.join("memory.stat"))
            .ok()
            .and_then(|stat| {
                stat.lines()
                    .find_map(|l| l.strip_prefix("file ")?.trim().parse::<u64>().ok())
            })
            .unwrap_or(0);
        match (read("memory.max"), read("memory.current")) {
            (Some(max), Some(current)) => max.saturating_sub(current.saturating_sub(file)),
            _ => 0,
        }
    }

    /// Kills every process in `vm-<name>`; the process owner reaps them and
    /// removes the cgroup.
    pub fn kill_vm(&self, name: &str) -> Result<()> {
        match fs::write(self.vm_dir(name).join("cgroup.kill"), b"1") {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            r => r.with_context(|| format!("cannot kill cgroup vm-{name}")),
        }
    }

    /// Kills every process in `vm-<name>` and removes the cgroup.
    pub async fn remove_vm(&self, name: &str) -> Result<()> {
        kill_and_remove(&self.vm_dir(name)).await
    }

    /// A tree at `root` (a temporary directory in tests).
    #[cfg(test)]
    pub(crate) fn at(root: PathBuf) -> Self {
        Self { root }
    }

    /// Kills and removes every `vm-*` cgroup. Called at daemon start, before
    /// the API accepts requests: VMs never outlive the daemon that started
    /// them. systemd's default `KillMode=control-group` already does this
    /// on a clean stop; this covers crashes and other kill modes.
    pub async fn remove_leftovers(&self) -> Result<()> {
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let is_vm = entry
                .file_name()
                .to_str()
                .is_some_and(|n| n.starts_with("vm-"));
            if is_vm && entry.file_type()?.is_dir() {
                tracing::warn!("removing leftover cgroup {}", entry.path().display());
                kill_and_remove(&entry.path()).await?;
            }
        }
        Ok(())
    }
}

/// The files and values that enforce `limits`.
fn limit_files(limits: Limits) -> [(&'static str, String); 4] {
    [
        ("memory.max", limits.memory_max_bytes.to_string()),
        ("memory.swap.max", "0".to_owned()),
        (
            "cpu.max",
            format!(
                "{} {CPU_PERIOD_US}",
                u64::from(limits.vcpus) * CPU_PERIOD_US
            ),
        ),
        ("pids.max", PIDS_MAX.to_string()),
    ]
}

/// Extracts the cgroup v2 path from `/proc/self/cgroup` (`0::/path`).
fn parse_own_cgroup(text: &str) -> Result<&str> {
    let path = text
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .context("no cgroup v2 entry in /proc/self/cgroup")?;
    if !path.starts_with('/') || path.split('/').any(|c| c == "..") {
        bail!("unexpected cgroup path {path:?}");
    }
    Ok(path)
}

/// Makes a helper program start in the `tools` leaf (1 GiB for all helpers
/// together). Does nothing before `Cgroups::setup`, e.g. in unit tests.
pub fn confine_tool(cmd: &mut Command) -> Result<()> {
    match TOOLS.get() {
        Some(dir) => move_on_exec(cmd, dir),
        None => Ok(()),
    }
}

/// Makes `cmd` join the cgroup at `dir` and raise its `oom_score_adj`
/// before `exec`, so the program never runs outside its limits. Registers
/// a `pre_exec` hook.
pub fn move_on_exec(cmd: &mut Command, dir: &Path) -> Result<()> {
    let procs = fs::OpenOptions::new()
        .write(true)
        .open(dir.join("cgroup.procs"))
        .with_context(|| format!("cannot open {}/cgroup.procs", dir.display()))?;
    // SAFETY: the closure runs in the forked child before exec. It only makes
    // raw syscalls through rustix (write, open, close) with no allocation,
    // locking or logging, which keeps it async-signal-safe.
    #[allow(unsafe_code)]
    unsafe {
        cmd.pre_exec(move || {
            rustix::io::write(&procs, b"0")?;
            let adj = rustix::fs::open(
                c"/proc/self/oom_score_adj",
                rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )?;
            rustix::io::write(&adj, OOM_SCORE_ADJ)?;
            Ok(())
        });
    }
    Ok(())
}

/// Kills every process in the cgroup at `dir`, waits until it is empty (at
/// most 10 s) and removes it. A missing cgroup is not an error.
async fn kill_and_remove(dir: &Path) -> Result<()> {
    match fs::write(dir.join("cgroup.kill"), b"1") {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        r => r.with_context(|| format!("cannot kill cgroup {}", dir.display()))?,
    }
    for _ in 0..1000 {
        let events = match fs::read_to_string(dir.join("cgroup.events")) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            r => r?,
        };
        if events.lines().any(|l| l == "populated 0") {
            // cgroup directories are removed with rmdir; their control files
            // go with them. Nothing else is ever deleted here.
            return match fs::remove_dir(dir) {
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                r => r.with_context(|| format!("cannot remove {}", dir.display())),
            };
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    bail!("cgroup {} still has processes after kill", dir.display())
}

fn create_dir(dir: &Path) -> Result<()> {
    match fs::create_dir(dir) {
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        r => r.with_context(|| format!("cannot create {}", dir.display())),
    }
}

fn write(path: &Path, value: &[u8]) -> Result<()> {
    fs::write(path, value).with_context(|| {
        format!(
            "cannot write {:?} to {}",
            String::from_utf8_lossy(value),
            path.display()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spawn_into(cmd: &mut Command, dir: &Path) -> Result<tokio::process::Child> {
        move_on_exec(cmd, dir)?;
        Ok(cmd.spawn()?)
    }

    #[test]
    fn parses_own_cgroup() {
        let text =
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/stallod-dev.service\n";
        assert_eq!(
            parse_own_cgroup(text).unwrap(),
            "/user.slice/user-1000.slice/user@1000.service/app.slice/stallod-dev.service"
        );
        assert!(parse_own_cgroup("1:name=systemd:/x\n").is_err());
        assert!(parse_own_cgroup("0::/a/../b\n").is_err());
        assert!(parse_own_cgroup("0::relative\n").is_err());
    }

    #[test]
    fn limits_become_cgroup_files() {
        let files = limit_files(Limits {
            memory_max_bytes: 2304 << 20,
            vcpus: 2,
        });
        assert_eq!(
            files,
            [
                ("memory.max", "2415919104".to_owned()),
                ("memory.swap.max", "0".to_owned()),
                ("cpu.max", "200000 100000".to_owned()),
                ("pids.max", "512".to_owned()),
            ]
        );
    }

    #[test]
    fn setup_moves_into_leaf_and_enables_controllers() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        fs::write(
            root.join("cgroup.controllers"),
            "cpuset cpu io memory pids\n",
        )
        .unwrap();
        Cgroups::setup_at(root.clone(), 4242).unwrap();
        let read = |p: &str| fs::read_to_string(root.join(p)).unwrap();
        assert_eq!(read("daemon/cgroup.procs"), "4242");
        assert_eq!(read("cgroup.subtree_control"), "+cpu +memory +pids");
        assert_eq!(read("tools/memory.max"), "1G");
        assert!(!root.join("daemon/memory.max").exists());
    }

    #[test]
    fn setup_fails_closed_without_controllers() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("cgroup.controllers"), "cpu pids\n").unwrap();
        let err = Cgroups::setup_at(dir.path().to_path_buf(), 1).unwrap_err();
        assert!(err.to_string().contains("memory"), "{err:#}");
        assert!(!dir.path().join("daemon").exists());
    }

    #[tokio::test]
    async fn create_vm_writes_limits() {
        let dir = tempfile::tempdir().unwrap();
        let cg = Cgroups {
            root: dir.path().to_path_buf(),
        };
        let limits = Limits {
            memory_max_bytes: 1 << 30,
            vcpus: 1,
        };
        let vm = cg.create_vm("dev", limits).await.unwrap();
        assert_eq!(vm, dir.path().join("vm-dev"));
        // Without cgroup.kill/events (a plain directory), it cannot be
        // cleared, and an existing directory is never silently reused.
        assert!(cg.create_vm("dev", limits).await.is_err());

        fs::write(vm.join("memory.current"), "1048576\n").unwrap();
        assert_eq!(cg.unused_memory_bytes("dev"), (1 << 30) - (1 << 20));
        // Page cache in the VM's cgroup is not memory it still takes.
        fs::write(
            vm.join("memory.stat"),
            "anon 524288\nfile 524288\nfile_dirty 0\n",
        )
        .unwrap();
        assert_eq!(cg.unused_memory_bytes("dev"), (1 << 30) - (1 << 19));
        assert_eq!(cg.unused_memory_bytes("none"), 0);
        assert_eq!(
            fs::read_to_string(vm.join("cpu.max")).unwrap(),
            "100000 100000"
        );
        assert_eq!(
            fs::read_to_string(vm.join("memory.max")).unwrap(),
            "1073741824"
        );
    }

    /// Real cgroup v2 limits under systemd delegation, no VM: the test
    /// re-runs itself as a transient user service with `Delegate=yes`, then
    /// spawns a 256 MiB allocation into a 64 MiB cgroup and expects the
    /// kernel to OOM-kill it. Run with `cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn real_limits_under_delegation() {
        if std::env::var_os("STALLO_DELEGATED").is_none() {
            let exe = std::env::current_exe().unwrap();
            let status = std::process::Command::new("systemd-run")
                .args(["--user", "--pipe", "--wait", "--collect", "--quiet"])
                .args(["-p", "Delegate=yes", "-E", "STALLO_DELEGATED=1"])
                .arg(exe)
                .args([
                    "--ignored",
                    "--exact",
                    "cgroup::tests::real_limits_under_delegation",
                ])
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let cg = Cgroups::setup().unwrap();

                // A leftover VM cgroup with a process is killed and removed;
                // the daemon leaf is left alone.
                let old = cg.root.join("vm-leftover");
                fs::create_dir(&old).unwrap();
                let mut orphan = spawn_into(Command::new("sleep").arg("30"), &old).unwrap();
                cg.remove_leftovers().await.unwrap();
                assert!(!old.exists());
                assert!(cg.root.join("daemon").exists());
                let _ = orphan.wait().await;

                // Spawning into a missing cgroup fails instead of running
                // the program unconfined.
                assert!(spawn_into(&mut Command::new("true"), &old).is_err());

                // Helpers run in the tools leaf.
                let mut cmd = Command::new("cat");
                cmd.arg("/proc/self/cgroup");
                confine_tool(&mut cmd).unwrap();
                let out = cmd.output().await.unwrap();
                assert!(
                    String::from_utf8_lossy(&out.stdout)
                        .trim_end()
                        .ends_with("/tools")
                );

                let limits = Limits {
                    memory_max_bytes: 64 << 20,
                    vcpus: 1,
                };
                let dir = cg.create_vm("limit-test", limits).await.unwrap();
                assert_eq!(
                    fs::read_to_string(dir.join("pids.max")).unwrap().trim(),
                    "512"
                );

                // oom_score_adj is set before exec.
                let mut sleeper = spawn_into(Command::new("sleep").arg("30"), &dir).unwrap();
                let pid = sleeper.id().unwrap();
                let adj = fs::read_to_string(format!("/proc/{pid}/oom_score_adj")).unwrap();
                assert_eq!(adj.trim(), "500");
                let procs = fs::read_to_string(dir.join("cgroup.procs")).unwrap();
                assert!(procs.lines().any(|l| l == pid.to_string()));

                // 256 MiB buffer in a 64 MiB cgroup without swap: OOM kill.
                let mut cmd = Command::new("dd");
                cmd.args(["if=/dev/zero", "of=/dev/null", "bs=256M", "count=1"])
                    .stderr(std::process::Stdio::null());
                let status = spawn_into(&mut cmd, &dir).unwrap().wait().await.unwrap();
                use std::os::unix::process::ExitStatusExt;
                assert_eq!(status.signal(), Some(9), "{status:?}");
                let events = fs::read_to_string(dir.join("memory.events")).unwrap();
                assert!(!events.contains("oom_kill 0"), "{events}");

                cg.remove_vm("limit-test").await.unwrap();
                assert!(!dir.exists());
                let _ = sleeper.wait().await;
            });
    }
}
