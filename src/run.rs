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
        // A clone would carry a copy of the source's machine identity
        // (firmware variables, TPM), and `exec` runs Linux commands only.
        ensure!(
            src.machine.is_linux(),
            "{source} is a Windows VM; `stallo run` is for Linux VMs"
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
    /// to the seed (VMs from ISOs have none), and `vm.toml` last.
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
        if from.join(qemu::SEED).exists() {
            fs::hard_link(from.join(qemu::SEED), to.join(qemu::SEED))?;
        }
        VmConfig {
            name: name.to_owned(),
            uuid: new_uuid()?,
            agent_control: false,
            throwaway_of: Some(src.name.clone()),
            // A run only needs the guest agent, not the source's ports.
            forwards: vec![],
            vnc: false,
            ..src.clone()
        }
        .save(&to)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cgroup::Cgroups;
    use crate::config::{DaemonConfig, Mode, NetProfile};
    use crate::images::Os;
    use crate::paths::Paths;

    fn manager(root: &std::path::Path) -> Arc<Manager> {
        manager_in(root, Mode::Dev)
    }

    fn manager_in(root: &std::path::Path, mode: Mode) -> Arc<Manager> {
        for d in ["data", "run", "cg"] {
            fs::create_dir(root.join(d)).unwrap();
        }
        let paths = Paths::new(root.join("data"), root.join("run"))
            .unwrap()
            .prepare()
            .unwrap();
        Manager::new(
            paths,
            DaemonConfig::default(),
            Cgroups::at(root.join("cg")),
            mode,
        )
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
            vnc: false,
            cdrom: None,
            machine: Os::Linux,
        }
    }

    /// VNC: a human setting, saved in vm.toml; never on run clones. The
    /// socket directories are shared with group `stallo` in production only.
    #[tokio::test]
    async fn vnc_setting_and_modes() {
        use std::os::unix::fs::PermissionsExt;
        for (mode, want) in [(Mode::Dev, 0o700), (Mode::Production, 0o750)] {
            let tmp = tempfile::tempdir().unwrap();
            let m = manager_in(&fs::canonicalize(tmp.path()).unwrap(), mode);
            m.cleanup_leftovers().await.unwrap();
            let got = fs::metadata(m.paths.vnc_root())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(got & 0o777, want, "{mode:?}");
            for cfg in [vm("dev", None), vm("run-0a1b2c3d", Some("dev"))] {
                let dir = m.paths.vm_dir(&cfg.name);
                fs::create_dir(&dir).unwrap();
                cfg.save(&dir).unwrap();
            }
            m.set_vnc("dev", true).await.unwrap();
            assert!(m.load("dev").unwrap().vnc);
            m.set_vnc("dev", false).await.unwrap();
            assert!(!m.load("dev").unwrap().vnc);
            assert!(m.set_vnc("run-0a1b2c3d", true).await.is_err());
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

    /// `images rm` is refused while a VM uses the image: a stopped VM, a
    /// run clone, or a VM whose disk backs onto it; and while a VM
    /// directory's vm.toml cannot be read (fail closed).
    #[tokio::test]
    async fn image_rm_refused_while_in_use() {
        let tmp = tempfile::tempdir().unwrap();
        let m = manager(&fs::canonicalize(tmp.path()).unwrap());
        m.cleanup_leftovers().await.unwrap();
        let err = m.remove_image("ubuntu-26.04").await.unwrap_err();
        assert!(err.to_string().contains("not pulled"), "{err}");
        let images = m.paths.images_dir();
        crate::paths::ensure_private_dir(&images).unwrap();
        let base = crate::images::image_path(&m.paths, "ubuntu-26.04");
        fs::write(&base, b"qcow2").unwrap();
        crate::paths::ensure_private_dir(&crate::images::debs_dir(&m.paths, "ubuntu-26.04"))
            .unwrap();
        let mut other = vm("other", None);
        other.image = "ubuntu-24.04".into();
        for cfg in [vm("dev", None), vm("run-0a1b2c3d", Some("dev")), other] {
            let dir = m.paths.vm_dir(&cfg.name);
            fs::create_dir(&dir).unwrap();
            cfg.save(&dir).unwrap();
        }
        let err = m.remove_image("ubuntu-26.04").await.unwrap_err();
        assert!(
            err.to_string()
                .contains("in use by dev, run-0a1b2c3d; remove those VMs first"),
            "{err}"
        );
        for name in ["dev", "run-0a1b2c3d"] {
            fs::remove_dir_all(m.paths.vm_dir(name)).unwrap();
        }
        // A VM whose disk backs onto the image, whatever its vm.toml says.
        let half = m.paths.vm_dir("half");
        fs::create_dir(&half).unwrap();
        vm("half", None).save(&half).unwrap();
        let mut toml = fs::read_to_string(half.join("vm.toml")).unwrap();
        toml = toml.replace("ubuntu-26.04", "ubuntu-24.04");
        fs::write(half.join("vm.toml"), toml).unwrap();
        let ok = std::process::Command::new("qemu-img")
            .args(["create", "-q", "-f", "qcow2", "-u", "-F", "qcow2", "-b"])
            .arg(&base)
            .arg(half.join(qemu::DISK))
            .arg("1G")
            .status()
            .unwrap()
            .success();
        assert!(ok);
        let err = m.remove_image("ubuntu-26.04").await.unwrap_err();
        assert!(err.to_string().contains("in use by half"), "{err}");
        // A VM directory without a readable vm.toml might use any image.
        for toml in [None, Some("not toml")] {
            match toml {
                None => fs::remove_file(half.join("vm.toml")).unwrap(),
                Some(t) => fs::write(half.join("vm.toml"), t).unwrap(),
            }
            let err = m.remove_image("ubuntu-26.04").await.unwrap_err();
            assert!(
                err.to_string()
                    .contains("cannot tell whether half uses image ubuntu-26.04; if a `stallo run` is in progress, try again when it ends, otherwise remove it first (stallo rm half) or move it out of the vms directory"),
                "{err}"
            );
        }
        assert!(base.exists());
        fs::remove_dir_all(&half).unwrap();
        m.remove_image("ubuntu-26.04").await.unwrap();
        assert!(!base.exists());
        assert!(!crate::images::debs_dir(&m.paths, "ubuntu-26.04").exists());
        assert!(m.remove_image("ubuntu-26.04").await.is_err());
        assert!(m.remove_image("../x").await.is_err());
    }

    /// VMs from installer ISOs: agents may not create one, even from a
    /// pulled ISO; its blank disk backs onto nothing; a run clone of it
    /// needs no seed; and `images rm` keeps an ISO that is in a drive.
    #[tokio::test]
    async fn iso_vms() {
        let tmp = tempfile::tempdir().unwrap();
        let m = manager(&fs::canonicalize(tmp.path()).unwrap());
        m.cleanup_leftovers().await.unwrap();
        let id = "fedora-44-workstation";
        crate::paths::ensure_private_dir(&m.paths.images_dir()).unwrap();
        fs::write(crate::images::iso_path(&m.paths, id), b"iso").unwrap();
        let new = crate::vm::NewVm {
            name: "desk".into(),
            image: id.into(),
            vcpus: 2,
            memory_mib: 4096,
            disk_gib: 32,
            net: NetProfile::Offline,
            forwards: vec![],
            agent_control: true,
            may_pull: false,
            vnc: false,
        };
        let err = m.create(&new).await.unwrap_err();
        assert_eq!(
            err.to_string(),
            "agents may not create VMs from installer ISOs"
        );
        assert!(!m.paths.vm_dir("desk").exists());

        // The files `create` makes (but the firmware variables, which need
        // OVMF on the host).
        let dir = m.paths.vm_dir("desk");
        fs::create_dir(&dir).unwrap();
        qemu::create_disk(None, &dir.join(qemu::DISK), 1)
            .await
            .unwrap();
        assert_eq!(
            crate::images::backing_file(&dir.join(qemu::DISK)).unwrap(),
            None
        );
        fs::write(dir.join(qemu::VARS), b"vars").unwrap();
        let cfg = VmConfig {
            image: id.into(),
            cdrom: Some(id.into()),
            vnc: true,
            ..vm("desk", None)
        };
        cfg.save(&dir).unwrap();

        let clone = "run-0a1b2c3d";
        fs::create_dir(m.paths.vm_dir(clone)).unwrap();
        m.clone_files(&cfg, clone).await.unwrap();
        assert_eq!(m.load(clone).unwrap().cdrom.as_deref(), Some(id));
        assert!(!m.paths.vm_dir(clone).join(qemu::SEED).exists());

        let err = m.remove_image(id).await.unwrap_err();
        assert!(
            err.to_string().contains("in use by desk, run-0a1b2c3d"),
            "{err}"
        );
        // The drive alone counts too (a VM made from another ISO).
        fs::remove_dir_all(m.paths.vm_dir(clone)).unwrap();
        VmConfig {
            image: "ubuntu-26.04-desktop".into(),
            ..cfg
        }
        .save(&dir)
        .unwrap();
        let err = m.remove_image(id).await.unwrap_err();
        assert!(err.to_string().contains("in use by desk"), "{err}");
        fs::remove_dir_all(&dir).unwrap();
        m.remove_image(id).await.unwrap();
        assert!(!crate::images::iso_path(&m.paths, id).exists());
    }

    /// `set_cdrom`: only VMs made from an ISO (no run clones), only pulled
    /// installer ISOs; saved in vm.toml, nothing else changes.
    #[tokio::test]
    async fn cdrom_setting() {
        let tmp = tempfile::tempdir().unwrap();
        let m = manager(&fs::canonicalize(tmp.path()).unwrap());
        m.cleanup_leftovers().await.unwrap();
        let id = "fedora-44-workstation";
        crate::paths::ensure_private_dir(&m.paths.images_dir()).unwrap();
        fs::write(crate::images::iso_path(&m.paths, id), b"iso").unwrap();
        let desk = VmConfig {
            image: id.into(),
            cdrom: Some(id.into()),
            vnc: true,
            ..vm("desk", None)
        };
        let clone = VmConfig {
            name: "run-0a1b2c3d".into(),
            throwaway_of: Some("desk".into()),
            ..desk.clone()
        };
        for cfg in [&desk, &clone, &vm("dev", None)] {
            let dir = m.paths.vm_dir(&cfg.name);
            fs::create_dir(&dir).unwrap();
            cfg.save(&dir).unwrap();
        }
        let err = |r: Result<()>| r.unwrap_err().to_string();

        m.set_cdrom("desk", None).await.unwrap();
        let ejected = m.load("desk").unwrap();
        assert_eq!(
            ejected,
            VmConfig {
                cdrom: None,
                ..desk.clone()
            }
        );
        m.set_cdrom("desk", Some(id)).await.unwrap();
        assert_eq!(m.load("desk").unwrap(), desk);

        for (vm, iso, want) in [
            ("desk", Some("ubuntu-26.04-desktop"), "not pulled"),
            ("desk", Some("ubuntu-26.04"), "is not an installer ISO"),
            ("desk", Some("nope"), "unknown image"),
            ("desk", Some("../x"), "invalid"),
            ("dev", None, "dev has no CD-ROM drive"),
            ("dev", Some(id), "dev has no CD-ROM drive"),
            ("run-0a1b2c3d", None, "clone"),
            ("nope", None, "no VM named nope"),
        ] {
            let e = err(m.set_cdrom(vm, iso).await);
            assert!(e.contains(want), "{vm} {iso:?}: {e}");
        }
        // A pull or removal holds the images lock: refused, not waited for.
        let held = m.images.write().await;
        let e = err(m.set_cdrom("desk", None).await);
        assert!(e.contains("image pull or removal is in progress"), "{e}");
        drop(held);
        assert_eq!(m.load("desk").unwrap(), desk, "nothing saved");
        assert_eq!(m.load("dev").unwrap(), vm("dev", None));
    }

    /// A pull is refused before any download unless its pull reserve fits
    /// above the disk floor; a cached image needs no space.
    #[tokio::test]
    async fn pull_needs_free_space() {
        let tmp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(tmp.path()).unwrap();
        for d in ["data", "run", "cg"] {
            fs::create_dir(root.join(d)).unwrap();
        }
        let paths = Paths::new(root.join("data"), root.join("run"))
            .unwrap()
            .prepare()
            .unwrap();
        let mut config = DaemonConfig::default();
        // No disk has a 1 PiB floor free.
        config.host.disk_floor_gib = 1 << 20;
        let m = Manager::new(paths, config, Cgroups::at(root.join("cg")), Mode::Dev);
        let err = m.pull("arch").await.unwrap_err();
        assert!(
            err.to_string()
                .contains("not enough disk space to download the image"),
            "{err}"
        );
        assert!(!m.paths.images_dir().join(".partial-arch").exists());
        fs::write(crate::images::image_path(&m.paths, "arch"), b"qcow2").unwrap();
        m.pull("arch").await.unwrap();
    }

    /// An agent's `new` (no pulls) needs a pulled image, checked under the
    /// images lock: nothing is downloaded and no VM directory is made.
    #[tokio::test]
    async fn agent_create_needs_a_pulled_image() {
        let tmp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(tmp.path()).unwrap();
        for d in ["data", "run", "cg"] {
            fs::create_dir(root.join(d)).unwrap();
        }
        let paths = Paths::new(root.join("data"), root.join("run"))
            .unwrap()
            .prepare()
            .unwrap();
        let mut config = DaemonConfig::default();
        // Admission must pass on any test host's disk.
        config.host.disk_floor_gib = 0;
        let m = Manager::new(paths, config, Cgroups::at(root.join("cg")), Mode::Dev);
        m.cleanup_leftovers().await.unwrap();
        let new = crate::vm::NewVm {
            name: "agent".into(),
            image: "ubuntu-26.04".into(),
            vcpus: 1,
            memory_mib: 512,
            disk_gib: 1,
            net: NetProfile::Offline,
            forwards: vec![],
            agent_control: true,
            may_pull: false,
            vnc: false,
        };
        let err = m.create(&new).await.unwrap_err();
        assert!(
            err.to_string().contains("image ubuntu-26.04 not pulled"),
            "{err}"
        );
        assert!(!m.paths.vm_dir("agent").exists());
        assert!(!m.paths.images_dir().join(".partial-ubuntu-26.04").exists());
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
            may_pull: true,
            vnc: false,
        };
        let err = m.create(&new).await.unwrap_err();
        assert!(err.to_string().contains("kept for `stallo run`"), "{err}");
    }

    /// S15, fail closed: dev mode always refuses the internet profile, and
    /// production mode refuses it without the host's table (as here). It
    /// is neither created nor started, also from a hand-written vm.toml.
    #[tokio::test]
    async fn internet_is_refused() {
        for (mode, why) in [
            (Mode::Dev, "dev mode"),
            (Mode::Production, "isolation unavailable"),
        ] {
            internet_is_refused_in(mode, why).await;
        }
    }

    /// Images not verified with the internet profile refuse it, in both
    /// modes and before the isolation check.
    #[tokio::test]
    async fn internet_is_refused_for_unverified_images() {
        let why = "arch: the internet profile is not supported for this image yet";
        for mode in [Mode::Dev, Mode::Production] {
            let tmp = tempfile::tempdir().unwrap();
            let m = manager_in(&fs::canonicalize(tmp.path()).unwrap(), mode);
            let new = crate::vm::NewVm {
                name: "web".into(),
                image: "arch".into(),
                vcpus: 1,
                memory_mib: 512,
                disk_gib: 10,
                net: NetProfile::Internet,
                forwards: vec![],
                agent_control: false,
                may_pull: true,
                vnc: false,
            };
            let err = m.create(&new).await.unwrap_err();
            assert_eq!(err.to_string(), why);
            assert!(!m.paths.vm_dir("web").exists());

            let dir = m.paths.vm_dir("web");
            fs::create_dir_all(&dir).unwrap();
            let cfg = VmConfig {
                net: NetProfile::Internet,
                image: "arch".into(),
                ..vm("web", None)
            };
            cfg.save(&dir).unwrap();
            let err = m.start("web").await.err().unwrap();
            assert_eq!(err.to_string(), why);
        }
    }

    /// A Windows VM fails closed: no internet, no `stallo run` clone and
    /// nothing below its minimum size.
    #[tokio::test]
    async fn windows_vms_are_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let m = manager(&fs::canonicalize(tmp.path()).unwrap());
        m.cleanup_leftovers().await.unwrap();
        let win = VmConfig {
            machine: Os::Windows,
            vcpus: 2,
            memory_mib: 4096,
            disk_gib: 64,
            ..vm("win", None)
        };
        let dir = m.paths.vm_dir("win");
        fs::create_dir(&dir).unwrap();
        win.save(&dir).unwrap();
        let argv = ["true".to_owned()];
        let err = m
            .run("win", &argv, false, Duration::from_secs(5), async {})
            .await
            .unwrap_err();
        assert!(err.to_string().contains("is a Windows VM"), "{err}");
        assert_eq!(fs::read_dir(m.paths.vms_dir()).unwrap().count(), 1);
        let err = m.set_resources("win", Some(1), None).await.unwrap_err();
        assert!(err.to_string().contains("at least 2 vCPUs"), "{err}");
        assert_eq!(m.load("win").unwrap(), win);

        for mode in [Mode::Dev, Mode::Production] {
            let tmp = tempfile::tempdir().unwrap();
            let m = manager_in(&fs::canonicalize(tmp.path()).unwrap(), mode);
            let dir = m.paths.vm_dir("win");
            fs::create_dir_all(&dir).unwrap();
            VmConfig {
                net: NetProfile::Internet,
                ..win.clone()
            }
            .save(&dir)
            .unwrap();
            let err = m.start("win").await.err().unwrap();
            assert!(err.to_string().contains("offline only"), "{err}");
        }
    }

    async fn internet_is_refused_in(mode: Mode, why: &str) {
        let tmp = tempfile::tempdir().unwrap();
        let m = manager_in(&fs::canonicalize(tmp.path()).unwrap(), mode);
        let new = crate::vm::NewVm {
            name: "web".into(),
            image: "ubuntu-26.04".into(),
            vcpus: 1,
            memory_mib: 512,
            disk_gib: 10,
            net: NetProfile::Internet,
            forwards: vec![],
            agent_control: false,
            may_pull: true,
            vnc: false,
        };
        let err = m.create(&new).await.unwrap_err();
        assert!(err.to_string().contains(why), "{err}");
        assert!(!m.paths.vm_dir("web").exists());

        let dir = m.paths.vm_dir("web");
        fs::create_dir_all(&dir).unwrap();
        let cfg = VmConfig {
            net: NetProfile::Internet,
            ..vm("web", None)
        };
        cfg.save(&dir).unwrap();
        let err = m.start("web").await.err().unwrap();
        assert!(err.to_string().contains(why), "{err}");
    }
}
