//! `stallo run`: a command in a throwaway clone of a stopped VM.
//!
//! The clone's disk is a qcow2 overlay on the source VM's disk, so the
//! source never changes. The clone gets a copy of the firmware variables,
//! a new UUID and a temporary name (`run-<hex>`), boots, runs the command
//! and is removed again, whatever happens: on success, on error, and when
//! the client goes away (Ctrl-C). A daemon that dies mid-run leaves the
//! clone behind; the next daemon start removes it (names starting with
//! `run-` are kept for clones).
//!
//! The client going away is seen as the end of its request stream, so a
//! client must not half-close its connection while it waits.

use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use tokio::process::Command;

use crate::config::{VmConfig, new_uuid};
use crate::paths::safe_remove;
use crate::qga::ExecOutput;
use crate::vm::{EXEC_MAX_TIMEOUT, Manager, READY_TIMEOUT, RUN_PREFIX};
use crate::{qemu, run_tool};

/// Removes `name` from the set of VMs in a run when dropped (before the
/// lock guard taken with it, which is declared earlier).
struct InRun<'a>(&'a Manager, &'a str);

impl Drop for InRun<'_> {
    fn drop(&mut self) {
        self.0.in_run.lock().unwrap().remove(self.1);
    }
}

impl Manager {
    /// Runs `argv` (as in `exec`) in a throwaway clone of the stopped VM
    /// `source` and removes the clone afterwards. `cancel` resolves when the
    /// caller gives up; the command is then abandoned and the clone removed.
    ///
    /// The source and the clone stay locked for the whole run: the source
    /// may not start, change or go away while the clone reads its disk, and
    /// nobody else may start, stop or change the clone. Other operations on
    /// either are refused at once.
    pub async fn run(
        self: &Arc<Self>,
        source: &str,
        argv: &[String],
        admin: bool,
        limit: Duration,
        cancel: impl Future<Output = ()>,
    ) -> Result<ExecOutput> {
        ensure!(!argv.is_empty(), "nothing to run");
        ensure!(
            (Duration::from_secs(1)..=EXEC_MAX_TIMEOUT).contains(&limit),
            "timeout must be between 1 s and {EXEC_MAX_TIMEOUT:?}"
        );
        self.check_exists(source)?;
        let _op = self.lock_for_run(source)?;
        let _in_run = InRun(self, source);
        let src = self.load(source)?;
        ensure!(
            self.running(source).is_none(),
            "{source} is running; `stallo run` needs a stopped VM: stallo stop {source}"
        );
        ensure!(
            src.throwaway_of.is_none(),
            "{source} is itself the clone of a run"
        );

        let name = format!("{RUN_PREFIX}{}", &new_uuid()?[..8]);
        let _clone_op = self.lock_for_run(&name)?;
        let _clone_in_run = InRun(self, &name);
        let dir = self.paths.vm_dir(&name);
        // Claims the name atomically.
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .with_context(|| format!("cannot create {}", dir.display()))?;
        let work = async {
            self.clone_files(&src, &name).await?;
            self.start_locked(&name, false).await?;
            tokio::select! {
                out = async {
                    self.wait_ready(&name, READY_TIMEOUT).await?;
                    self.exec(&name, argv, admin, limit, None).await
                } => out,
                () = cancel => bail!("cancelled: the client went away"),
            }
        };
        let result = work.await;
        // Always: kill the clone and delete it.
        if self.running(&name).is_some()
            && let Err(e) = self.stop_locked(&name, true).await
        {
            tracing::error!("{name}: stop after run: {e:#}");
        }
        if let Err(e) = safe_remove(&self.paths.data, &dir) {
            tracing::error!("{name}: cannot remove the clone: {e:#}");
        }
        tracing::info!("{name}: run on {source} ended (ok: {})", result.is_ok());
        result
    }

    /// The clone's files: an overlay on the source disk (`-u`: qemu-img
    /// never opens the source, which a compromised QEMU may have crafted),
    /// a copy of the firmware variables, a fresh state image, a hard link
    /// to the seed, and `vm.toml` last.
    async fn clone_files(&self, src: &VmConfig, name: &str) -> Result<()> {
        let (from, to) = (self.paths.vm_dir(&src.name), self.paths.vm_dir(name));
        run_tool(
            Command::new("qemu-img")
                .args(["create", "-q", "-f", "qcow2", "-u", "-F", "qcow2", "-b"])
                .arg(from.join(qemu::DISK))
                .arg(to.join(qemu::DISK))
                .arg(format!("{}G", src.disk_gib)),
            Duration::from_secs(30),
        )
        .await
        .context("cannot create the clone's disk")?;
        fs::copy(from.join(qemu::VARS), to.join(qemu::VARS))?;
        crate::paths::ensure_private_dir(&to.join(qemu::STATES))?;
        fs::hard_link(from.join(qemu::SEED), to.join(qemu::SEED))?;
        VmConfig {
            name: name.to_owned(),
            uuid: new_uuid()?,
            agent_control: false,
            throwaway_of: Some(src.name.clone()),
            // A run only needs the guest agent, not the source's ports.
            forwards: vec![],
            ..src.clone()
        }
        .save(&to)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cgroup::Cgroups;
    use crate::config::{DaemonConfig, NetProfile};
    use crate::paths::Paths;

    fn manager(root: &std::path::Path) -> Arc<Manager> {
        for d in ["data", "run", "cg"] {
            fs::create_dir(root.join(d)).unwrap();
        }
        let paths = Paths::new(root.join("data"), root.join("run"))
            .unwrap()
            .prepare()
            .unwrap();
        Manager::new(paths, DaemonConfig::default(), Cgroups::at(root.join("cg")))
    }

    fn vm(name: &str, throwaway_of: Option<&str>) -> VmConfig {
        VmConfig {
            name: name.into(),
            uuid: "4f1c2b9e-0d3a-4c5e-8f7a-1b2c3d4e5f60".into(),
            image: "ubuntu-26.04".into(),
            vcpus: 1,
            memory_mib: 512,
            disk_gib: 10,
            net: NetProfile::Offline,
            agent_control: false,
            throwaway_of: throwaway_of.map(Into::into),
            forwards: vec![],
        }
    }

    #[tokio::test]
    async fn leftover_clones_are_removed_at_start() {
        let tmp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(tmp.path()).unwrap();
        let m = manager(&root);
        m.cleanup_leftovers().await.unwrap();
        for cfg in [vm("dev", None), vm("run-0a1b2c3d", Some("dev"))] {
            let dir = m.paths.vm_dir(&cfg.name);
            fs::create_dir(&dir).unwrap();
            cfg.save(&dir).unwrap();
        }
        m.cleanup_leftovers().await.unwrap();
        let names: Vec<String> = m.list().unwrap().into_iter().map(|c| c.name).collect();
        assert_eq!(names, ["dev"]);
    }

    #[tokio::test]
    async fn a_vm_in_a_run_is_refused_at_once() {
        let tmp = tempfile::tempdir().unwrap();
        let m = manager(&fs::canonicalize(tmp.path()).unwrap());
        let held = m.lock("dev").await.unwrap();
        m.in_run.lock().unwrap().insert("dev".into());
        let err = m.lock("dev").await.unwrap_err();
        assert!(err.to_string().contains("in use by `stallo run`"), "{err}");
        drop(InRun(&m, "dev"));
        drop(held);
        // Free again: an ordinary wait-then-take.
        let held = m.lock("dev").await.unwrap();
        let err = m.lock_for_run("dev").unwrap_err();
        assert!(err.to_string().contains("busy"), "{err}");
        drop(held);
    }

    #[tokio::test]
    async fn a_failed_run_leaves_nothing_behind() {
        let tmp = tempfile::tempdir().unwrap();
        let m = manager(&fs::canonicalize(tmp.path()).unwrap());
        m.cleanup_leftovers().await.unwrap();
        // A source without its files: making the clone fails.
        let dir = m.paths.vm_dir("dev");
        fs::create_dir(&dir).unwrap();
        vm("dev", None).save(&dir).unwrap();
        let argv = ["true".to_owned()];
        let t = Duration::from_secs(5);
        assert!(m.run("dev", &argv, false, t, async {}).await.is_err());
        assert_eq!(fs::read_dir(m.paths.vms_dir()).unwrap().count(), 1);
        assert!(m.in_run.lock().unwrap().is_empty());
        assert!(m.lock_for_run("dev").is_ok(), "the source is free again");
        let bad = m.run("dev", &argv, false, Duration::ZERO, async {}).await;
        assert!(bad.unwrap_err().to_string().contains("timeout"));
    }

    #[tokio::test]
    async fn clone_names_are_reserved() {
        let tmp = tempfile::tempdir().unwrap();
        let m = manager(&fs::canonicalize(tmp.path()).unwrap());
        let new = crate::vm::NewVm {
            name: "run-1234".into(),
            image: "ubuntu-26.04".into(),
            vcpus: 1,
            memory_mib: 512,
            disk_gib: 10,
            net: NetProfile::Offline,
            forwards: vec![],
            agent_control: false,
        };
        let err = m.create(&new).await.unwrap_err();
        assert!(err.to_string().contains("kept for `stallo run`"), "{err}");
    }

    /// Fail closed: without an isolation check, internet VMs neither get
    /// created nor start (also from a hand-written vm.toml).
    #[tokio::test]
    async fn internet_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let m = manager(&fs::canonicalize(tmp.path()).unwrap());
        let new = crate::vm::NewVm {
            name: "web".into(),
            image: "ubuntu-26.04".into(),
            vcpus: 1,
            memory_mib: 512,
            disk_gib: 10,
            net: NetProfile::Internet,
            forwards: vec![],
            agent_control: false,
        };
        let err = m.create(&new).await.unwrap_err();
        assert!(err.to_string().contains("isolation unavailable"), "{err}");
        assert!(!m.paths.vm_dir("web").exists());

        let dir = m.paths.vm_dir("web");
        fs::create_dir_all(&dir).unwrap();
        let cfg = VmConfig {
            net: NetProfile::Internet,
            ..vm("web", None)
        };
        cfg.save(&dir).unwrap();
        let err = m.start("web").await.err().unwrap();
        assert!(err.to_string().contains("isolation unavailable"), "{err}");
    }
}
