//! cloud-init NoCloud seed ISO for offline Linux guests.
//!
//! The ISO (volume label `CIDATA`) carries `meta-data`, `user-data`,
//! `network-config` and, for images without one, the guest-agent `.deb`s.
//! On first boot cloud-init creates the `agent` user and installs the guest
//! agent from the ISO, since an offline guest has no package mirror.

use std::fs;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::config::{NetProfile, VmConfig};
use crate::images::{Agent, CatalogEntry};
use crate::paths::safe_remove;
use crate::run_tool;

/// The guest user that agents and humans log in as.
pub const GUEST_USER: &str = "agent";

/// Rendered seed files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seed {
    pub meta_data: String,
    pub user_data: String,
    pub network_config: String,
}

/// Renders the seed for `vm`, made from `image`. `password_hash` is a
/// SHA-512 crypt string.
pub fn render(vm: &VmConfig, password_hash: &str, image: &CatalogEntry) -> Result<Seed> {
    // The name and uuid go into YAML; never trust the caller.
    vm.validate()?;
    ensure!(
        password_hash.starts_with("$6$")
            && password_hash
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'$' | b'.' | b'/')),
        "unexpected password hash format"
    );
    let meta_data = format!("instance-id: {}\nlocal-hostname: {}\n", vm.uuid, vm.name);
    // The console logs in before the agent answers, so "ready" includes
    // it: a preinstalled agent starts only after cloud-init's final stage
    // (qemu.rs), and a .deb one is installed and started last.
    let mut runcmd = String::new();
    if image.qga_permissive {
        // SELinux confines the guest agent (virt_qemu_ga_t), so exec could
        // neither start its systemd-run scope nor switch to the guest user.
        // Only that domain becomes permissive, which leaves it as
        // unconfined as Ubuntu's agent. The module stays installed. If that
        // fails, the agent is masked for good (it has not started yet, see
        // qemu.rs): the VM never reports ready with an agent that cannot
        // exec, and `stallo new` times out instead.
        runcmd.push_str(
            "  - [sh, -c, \"echo '(typepermissive virt_qemu_ga_t)' > /run/stallo_qga.cil && semodule -i /run/stallo_qga.cil || systemctl mask --now qemu-guest-agent\"]\n",
        );
    }
    runcmd.push_str("  - [sh, -c, \"systemctl daemon-reload && systemctl restart getty@tty1\"]\n");
    if image.agent == Agent::Deb {
        runcmd.push_str("  - [sh, -c, \"mkdir -p /run/stallo-seed && mount -o ro LABEL=CIDATA /run/stallo-seed && dpkg -i /run/stallo-seed/debs/*.deb; umount /run/stallo-seed; systemctl start qemu-guest-agent\"]\n");
    }
    let user_data = format!(
        r#"#cloud-config
users:
  - name: {GUEST_USER}
    # sudo with the password, as Ubuntu's `sudo` group grants; portable to
    # distributions without that group.
    sudo: ["ALL=(ALL:ALL) ALL"]
    shell: /bin/bash
    lock_passwd: false
    passwd: "{password_hash}"
disable_root: true
ssh_pwauth: false
write_files:
  # The console logs in by itself: only the daemon reaches it (QMP), and
  # agents that may use it can already run commands as this user.
  - path: /etc/systemd/system/getty@tty1.service.d/autologin.conf
    content: |
      [Service]
      ExecStart=
      ExecStart=-/sbin/agetty --autologin {GUEST_USER} --noclear %I $TERM
runcmd:
{runcmd}"#
    );
    let network_config = match vm.net {
        // The offline profile has no network device, so the placeholder
        // never matches. Being optional, it makes netplan skip
        // systemd-networkd-wait-online, which would wait 2 minutes for a
        // link. That covers systemd < 256 (Ubuntu 24.04), where the
        // credential in qemu.rs is ignored; cloud-init reloads systemd
        // before the wait starts, so it holds on first boot too.
        NetProfile::Offline => {
            "version: 2\nethernets:\n  none:\n    match: {name: \"stallo-none\"}\n    optional: true\n"
        }
        // passt's DHCP. Matched by name, not MAC: a `stallo run` clone has
        // its own MAC but this disk's netplan file.
        NetProfile::Internet => {
            "version: 2\nethernets:\n  nic:\n    match: {name: \"en*\"}\n    dhcp4: true\n    dhcp6: true\n"
        }
    }
    .to_owned();
    Ok(Seed {
        meta_data,
        user_data,
        network_config,
    })
}

/// Writes the seed files to `work` (a fresh directory inside `root`, which
/// must be private: the files get default permissions) and builds `iso`
/// from them plus `debs`, if any. `work` is removed afterwards; `iso`
/// appears only when complete.
///
/// The ISO stays attached for the VM's life. It holds the password hash,
/// which the guest has anyway.
pub async fn build_iso(
    seed: &Seed,
    debs: Option<&Path>,
    root: &Path,
    work: &Path,
    iso: &Path,
) -> Result<()> {
    safe_remove(root, work)?;
    fs::create_dir(work)?;
    let files = [
        ("meta-data", &seed.meta_data),
        ("user-data", &seed.user_data),
        ("network-config", &seed.network_config),
    ];
    let partial = work.join("seed.iso");
    let mut cmd = Command::new("xorriso");
    cmd.args(["-as", "mkisofs", "-quiet", "-V", "CIDATA", "-J", "-R", "-o"])
        .arg(&partial)
        .arg("-graft-points");
    for (name, text) in files {
        fs::write(work.join(name), text)?;
        cmd.arg(graft(name, &work.join(name))?);
    }
    if let Some(debs) = debs {
        cmd.arg(graft("debs/", debs)?);
    }
    let result = run_tool(&mut cmd, Duration::from_secs(60))
        .await
        .context("cannot build the seed ISO")
        .and_then(|_| Ok(fs::rename(&partial, iso)?));
    safe_remove(root, work)?;
    result
}

/// `name=path` for `-graft-points`; `=` and `\` in the path would need
/// escaping, so they are refused.
fn graft(name: &str, path: &Path) -> Result<String> {
    let p = path.to_str().context("path is not UTF-8")?;
    if p.contains(['=', '\\']) {
        bail!("path {p:?} contains '=' or '\\'");
    }
    Ok(format!("{name}={p}"))
}

/// A random password: 24 characters from `[A-Za-z0-9]` (~142 bits).
pub fn generate_password() -> Result<String> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut out = String::with_capacity(24);
    while out.len() < 24 {
        for b in crate::random_bytes::<32>()? {
            // Rejection sampling keeps the distribution uniform.
            if (b as usize) < 248 && out.len() < 24 {
                out.push(ALPHABET[b as usize % ALPHABET.len()] as char);
            }
        }
    }
    Ok(out)
}

/// SHA-512 crypt hash via `openssl passwd -6`. The password goes through
/// stdin, never argv.
pub async fn hash_password(password: &str) -> Result<String> {
    let mut child = Command::new("openssl")
        .args(["passwd", "-6", "-stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .context("cannot run openssl")?;
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(format!("{password}\n").as_bytes()).await?;
    drop(stdin);
    let out = tokio::time::timeout(Duration::from_secs(10), child.wait_with_output())
        .await
        .context("openssl timed out")??;
    ensure!(out.status.success(), "openssl passwd failed");
    Ok(String::from_utf8(out.stdout)?.trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(id: &str) -> CatalogEntry {
        crate::images::find(id).unwrap()
    }

    fn vm() -> VmConfig {
        VmConfig {
            name: "dev".into(),
            uuid: "4f1c2b9e-0d3a-4c5e-8f7a-1b2c3d4e5f60".into(),
            image: "ubuntu-26.04".into(),
            vcpus: 2,
            memory_mib: 2048,
            disk_gib: 20,
            net: NetProfile::Offline,
            agent_control: false,
            throwaway_of: None,
            forwards: vec![],
            vnc: false,
            cdrom: None,
            machine: crate::images::Os::Linux,
        }
    }

    #[test]
    fn renders_seed() {
        let seed = render(&vm(), "$6$salt$abc./XYZ", &image("ubuntu-26.04")).unwrap();
        assert_eq!(
            seed.meta_data,
            "instance-id: 4f1c2b9e-0d3a-4c5e-8f7a-1b2c3d4e5f60\nlocal-hostname: dev\n"
        );
        assert!(seed.user_data.starts_with("#cloud-config\n"));
        assert!(seed.user_data.contains("passwd: \"$6$salt$abc./XYZ\""));
        assert!(
            seed.user_data
                .contains("agetty --autologin agent --noclear %I $TERM")
        );
        assert!(
            seed.user_data
                .contains("dpkg -i /run/stallo-seed/debs/*.deb")
        );
        assert!(
            seed.user_data
                .contains("    sudo: [\"ALL=(ALL:ALL) ALL\"]\n")
        );
        assert!(!seed.user_data.contains("groups:"));
        // Fedora: SELinux step, no dpkg step and no agent start (it starts
        // after cloud-init by itself); the rest is the same.
        let fedora = render(&vm(), "$6$salt$abc./XYZ", &image("fedora-44")).unwrap();
        let runcmd = |s: &Seed| s.user_data.split_once("runcmd:\n").unwrap().1.to_owned();
        assert_eq!(
            runcmd(&fedora),
            "  - [sh, -c, \"echo '(typepermissive virt_qemu_ga_t)' > /run/stallo_qga.cil && semodule -i /run/stallo_qga.cil || systemctl mask --now qemu-guest-agent\"]\n\
             \x20 - [sh, -c, \"systemctl daemon-reload && systemctl restart getty@tty1\"]\n"
        );
        assert_eq!(
            runcmd(&seed),
            "  - [sh, -c, \"systemctl daemon-reload && systemctl restart getty@tty1\"]\n\
             \x20 - [sh, -c, \"mkdir -p /run/stallo-seed && mount -o ro LABEL=CIDATA /run/stallo-seed && dpkg -i /run/stallo-seed/debs/*.deb; umount /run/stallo-seed; systemctl start qemu-guest-agent\"]\n"
        );
        let head = |s: &Seed| s.user_data.split_once("runcmd:\n").unwrap().0.to_owned();
        assert_eq!(head(&fedora), head(&seed));
        assert_eq!(
            seed.network_config,
            "version: 2\nethernets:\n  none:\n    match: {name: \"stallo-none\"}\n    optional: true\n"
        );
        let inet = VmConfig {
            net: NetProfile::Internet,
            ..vm()
        };
        let seed = render(&inet, "$6$salt$abc./XYZ", &image("ubuntu-26.04")).unwrap();
        assert_eq!(
            seed.network_config,
            "version: 2\nethernets:\n  nic:\n    match: {name: \"en*\"}\n    dhcp4: true\n    dhcp6: true\n"
        );
    }

    #[test]
    fn refuses_odd_hashes_and_names() {
        assert!(render(&vm(), "plain", &image("ubuntu-26.04")).is_err());
        let bad = VmConfig {
            name: "x\nruncmd: [reboot]".into(),
            ..vm()
        };
        assert!(render(&bad, "$6$s$h", &image("ubuntu-26.04")).is_err());
        assert!(render(&vm(), "$6$a\"\nruncmd: x", &image("ubuntu-26.04")).is_err());
    }

    #[test]
    fn passwords_are_random_alphanumeric() {
        let a = generate_password().unwrap();
        let b = generate_password().unwrap();
        assert_eq!(a.len(), 24);
        assert!(a.bytes().all(|c| c.is_ascii_alphanumeric()));
        assert_ne!(a, b);
    }

    #[tokio::test]
    async fn hashes_with_openssl() {
        let h = hash_password("secret").await.unwrap();
        assert!(h.starts_with("$6$"), "{h}");
        assert!(render(&vm(), &h, &image("ubuntu-26.04")).is_ok());
    }

    #[test]
    fn graft_points() {
        assert_eq!(
            graft("debs/", Path::new("/d/debs")).unwrap(),
            "debs/=/d/debs"
        );
        assert!(graft("x", Path::new("/a=b")).is_err());
    }

    /// Builds a real ISO with xorriso (no VM).
    #[tokio::test]
    async fn builds_iso() {
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        let debs = root.join("debs");
        fs::create_dir(&debs).unwrap();
        fs::write(debs.join("a.deb"), b"x").unwrap();
        let seed = render(&vm(), "$6$s$h", &image("ubuntu-26.04")).unwrap();
        build_iso(
            &seed,
            Some(&debs),
            &root,
            &root.join("seed"),
            &root.join("seed.iso"),
        )
        .await
        .unwrap();
        let iso = fs::read(root.join("seed.iso")).unwrap();
        // ISO 9660 volume id at 0x8028.
        assert_eq!(&iso[0x8028..0x802e], b"CIDATA");
        assert!(!root.join("seed").exists());
    }
}
