//! Configuration files (`stallod.toml` for the daemon, `vm.toml` per VM) and
//! validation of names that come from outside.

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};

/// VM names match `^[a-z][a-z0-9-]{0,30}$`.
pub const MAX_NAME_LEN: usize = 31;

/// 16 TiB: far above any host, and small enough that byte maths never
/// overflows.
pub const MAX_MEMORY_MIB: u64 = 1 << 24;

/// Checks a VM name. Names become directory names, cgroup names and QEMU
/// arguments, so the alphabet is tiny on purpose.
pub fn validate_name(name: &str) -> Result<()> {
    let b = name.as_bytes();
    let ok = (1..=MAX_NAME_LEN).contains(&b.len())
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-');
    ensure!(
        ok,
        "invalid VM name {name:?}: use 1-31 characters a-z, 0-9 and '-', starting with a letter"
    );
    Ok(())
}

/// Checks a snapshot tag: `^[A-Za-z][A-Za-z0-9._-]{0,63}$`. The leading
/// letter rules out `.`/`..`, option-like `-x` and all-digit tags, which QEMU
/// would also match against snapshot ids.
pub fn validate_tag(tag: &str) -> Result<()> {
    let ok = (1..=64).contains(&tag.len())
        && tag.as_bytes()[0].is_ascii_alphabetic()
        && tag
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'));
    ensure!(
        ok,
        "invalid snapshot name {tag:?}: use 1-64 characters A-Z, a-z, 0-9, '.', '_' and '-', starting with a letter"
    );
    Ok(())
}

/// Checks a catalog image id such as `ubuntu-26.04`:
/// `^[a-z][a-z0-9.-]{0,63}$`. Ids become file names in the image cache.
pub fn validate_image_id(id: &str) -> Result<()> {
    let b = id.as_bytes();
    let ok = (1..=64).contains(&b.len())
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'.' || c == b'-');
    ensure!(ok, "invalid image id {id:?}");
    Ok(())
}

/// Guest network profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetProfile {
    /// No network device at all.
    Offline,
    /// Internet only, enforced on the host (production mode, M3).
    Internet,
}

/// `<data>/vms/<name>/vm.toml`: the source of truth for one VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmConfig {
    pub name: String,
    pub uuid: String,
    /// Catalog image id the disk was created from.
    pub image: String,
    pub vcpus: u32,
    pub memory_mib: u64,
    pub disk_gib: u64,
    pub net: NetProfile,
    /// Whether agents (MCP) may control this VM. Off unless a human turns it
    /// on, or an agent created the VM (`agents_can_create`).
    #[serde(default)]
    pub agent_control: bool,
    /// Set on the throwaway clone of `stallo run`: the VM whose disk it
    /// overlays (read-only). Such a VM is removed when the run ends, and at
    /// daemon start if a run was cut off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub throwaway_of: Option<String>,
}

impl VmConfig {
    pub const FILE: &str = "vm.toml";

    pub fn validate(&self) -> Result<()> {
        validate_name(&self.name)?;
        validate_image_id(&self.image)?;
        ensure!(is_uuid(&self.uuid), "invalid uuid {:?}", self.uuid);
        if let Some(source) = &self.throwaway_of {
            validate_name(source)?;
            ensure!(*source != self.name, "a VM cannot overlay itself");
        }
        ensure!(
            (1..=255).contains(&self.vcpus),
            "vcpus must be between 1 and 255"
        );
        ensure!(
            (256..=MAX_MEMORY_MIB).contains(&self.memory_mib),
            "memory must be between 256 MiB and {MAX_MEMORY_MIB} MiB"
        );
        ensure!(
            (1..=16384).contains(&self.disk_gib),
            "disk must be between 1 and 16384 GiB"
        );
        Ok(())
    }

    /// Reads and validates `<dir>/vm.toml`. The VM name must match the
    /// directory name.
    pub fn load(dir: &Path) -> Result<Self> {
        let path = dir.join(Self::FILE);
        let text =
            fs::read_to_string(&path).with_context(|| format!("cannot read {}", path.display()))?;
        let cfg: Self =
            toml::from_str(&text).with_context(|| format!("invalid {}", path.display()))?;
        cfg.validate()
            .with_context(|| format!("invalid {}", path.display()))?;
        ensure!(
            dir.file_name() == Some(cfg.name.as_ref()),
            "{} names VM {:?}, which does not match its directory",
            path.display(),
            cfg.name
        );
        Ok(cfg)
    }

    /// Writes `<dir>/vm.toml` atomically and durably (new temp file, fsync,
    /// rename, fsync of the directory), mode 0640.
    pub fn save(&self, dir: &Path) -> Result<()> {
        self.validate()?;
        let tmp = dir.join(".vm.toml.tmp");
        match fs::remove_file(&tmp) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
            _ => {}
        }
        // create_new (O_EXCL) never follows a planted symlink.
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o640)
            .open(&tmp)
            .with_context(|| format!("cannot write {}", tmp.display()))?;
        f.write_all(toml::to_string(self)?.as_bytes())?;
        f.sync_all()?;
        fs::rename(&tmp, dir.join(Self::FILE))?;
        fs::File::open(dir)?.sync_all()?;
        Ok(())
    }
}

/// A random (version 4) UUID.
pub fn new_uuid() -> Result<String> {
    let mut b = crate::random_bytes::<16>()?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    ))
}

/// Lower-case hyphenated UUID, e.g. `4f1c2b9e-0d3a-4c5e-8f7a-1b2c3d4e5f60`.
fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, &c)| match i {
            8 | 13 | 18 | 23 => c == b'-',
            _ => c.is_ascii_digit() || (b'a'..=b'f').contains(&c),
        })
}

/// `<data>/stallod.toml`. Every key is optional.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DaemonConfig {
    pub host: HostConfig,
    /// Whether agents (MCP) may create VMs; such VMs start with agent
    /// control on. Agents never delete.
    pub agents_can_create: bool,
}

/// The `[host]` table: admission control and host protection.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HostConfig {
    /// Running VMs may use at most this share of MemTotal, in percent.
    pub memory_budget_pct: u64,
    /// MemAvailable that must remain after a VM starts, in MiB.
    pub reserve_mib: u64,
    /// Free space on the data filesystem that VMs may never eat into, in GiB.
    pub disk_floor_gib: u64,
    /// Minimum QEMU overhead on top of guest RAM, in MiB. The cgroup gets
    /// `memory.max = memory + max(this, memory / 16)`. Measured on Ubuntu
    /// 26.04 / QEMU 10.2 with a 2 GiB guest: QEMU's own RSS is about 60 MiB
    /// and the cgroup peaked 241 MiB above the resident guest RAM, page
    /// cache and kernel memory included.
    pub qemu_overhead_mib: u64,
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            memory_budget_pct: 50,
            reserve_mib: 4096,
            disk_floor_gib: 20,
            qemu_overhead_mib: 256,
        }
    }
}

impl DaemonConfig {
    /// Reads `path`, or returns the defaults if it does not exist.
    pub fn load(path: &Path) -> Result<Self> {
        let text = match fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
        };
        let cfg: Self =
            toml::from_str(&text).with_context(|| format!("invalid {}", path.display()))?;
        if !(1..=90).contains(&cfg.host.memory_budget_pct) {
            bail!("host.memory_budget_pct must be between 1 and 90");
        }
        ensure!(
            cfg.host.disk_floor_gib <= 1 << 20 && cfg.host.reserve_mib <= MAX_MEMORY_MIB,
            "host.disk_floor_gib or host.reserve_mib is out of range"
        );
        ensure!(
            cfg.host.qemu_overhead_mib <= MAX_MEMORY_MIB,
            "host.qemu_overhead_mib is out of range"
        );
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        for ok in ["a", "dev", "web-1", "a0-", &"a".repeat(31)] {
            assert!(validate_name(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "1a",
            "-a",
            "Dev",
            "a_b",
            "a.b",
            "a/b",
            "..",
            "a b",
            "é",
            "a\n",
            &"a".repeat(32),
        ] {
            assert!(validate_name(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn tags() {
        for ok in ["s1", "before-upgrade", "v1.2_x", &"A".repeat(64)] {
            assert!(validate_tag(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            ".",
            "..",
            "-x",
            "1",
            "12",
            "a b",
            "a/b",
            "a;b",
            "é",
            &"a".repeat(65),
        ] {
            assert!(validate_tag(bad).is_err(), "{bad:?}");
        }
        assert!(validate_image_id("ubuntu-26.04").is_ok());
        for bad in ["", "../x", "/etc/shadow", "Ubuntu", "a/b", "1x"] {
            assert!(validate_image_id(bad).is_err(), "{bad:?}");
        }
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
        }
    }

    #[test]
    fn vm_toml_round_trip_and_mode() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("dev");
        fs::create_dir(&dir).unwrap();
        // A stale or planted temp file is replaced, never written through.
        std::os::unix::fs::symlink("/nonexistent", dir.join(".vm.toml.tmp")).unwrap();
        vm().save(&dir).unwrap();
        vm().save(&dir).unwrap();
        assert_eq!(VmConfig::load(&dir).unwrap(), vm());
        let mode = fs::metadata(dir.join("vm.toml"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o640);
    }

    #[test]
    fn vm_toml_rejects_bad_values() {
        let bad = [
            VmConfig {
                name: "../x".into(),
                ..vm()
            },
            VmConfig {
                uuid: "not-a-uuid".into(),
                ..vm()
            },
            VmConfig { vcpus: 0, ..vm() },
            VmConfig {
                memory_mib: 1,
                ..vm()
            },
            VmConfig {
                memory_mib: MAX_MEMORY_MIB + 1,
                ..vm()
            },
            VmConfig {
                disk_gib: 0,
                ..vm()
            },
            VmConfig {
                image: "../x".into(),
                ..vm()
            },
            VmConfig {
                throwaway_of: Some("../x".into()),
                ..vm()
            },
            VmConfig {
                throwaway_of: Some("dev".into()),
                ..vm()
            },
        ];
        for cfg in bad {
            assert!(cfg.validate().is_err(), "{cfg:?}");
        }
        let other = tempfile::tempdir().unwrap();
        let wrong_dir = other.path().join("other");
        fs::create_dir(&wrong_dir).unwrap();
        vm().save(&wrong_dir).unwrap();
        assert!(VmConfig::load(&wrong_dir).is_err());

        let unknown = format!("{}extra = 1\n", toml::to_string(&vm()).unwrap());
        assert!(toml::from_str::<VmConfig>(&unknown).is_err());
    }

    #[test]
    fn uuids_are_valid_v4_and_unique() {
        let (a, b) = (new_uuid().unwrap(), new_uuid().unwrap());
        assert!(is_uuid(&a), "{a}");
        assert_eq!(&a[14..15], "4");
        assert!(matches!(&a[19..20], "8" | "9" | "a" | "b"));
        assert_ne!(a, b);
    }

    #[test]
    fn daemon_config_defaults_and_overrides() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stallod.toml");
        assert_eq!(DaemonConfig::load(&path).unwrap(), DaemonConfig::default());

        fs::write(&path, "[host]\nmemory_budget_pct = 25\n").unwrap();
        let cfg = DaemonConfig::load(&path).unwrap();
        assert_eq!(cfg.host.memory_budget_pct, 25);
        assert_eq!(cfg.host.reserve_mib, 4096);

        fs::write(&path, "[host]\nmemory_budget_pct = 0\n").unwrap();
        assert!(DaemonConfig::load(&path).is_err());
        fs::write(&path, "agents_can_create = true\n").unwrap();
        assert!(DaemonConfig::load(&path).unwrap().agents_can_create);
        fs::write(&path, "[host]\ntypo = 1\n").unwrap();
        assert!(DaemonConfig::load(&path).is_err());
    }
}
