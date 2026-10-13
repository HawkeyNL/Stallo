//! Host awareness: admission control, the `stallo host` summary and the disk
//! watchdog. The data directory shares a filesystem and RAM with other
//! services, so VMs only start when they fit, and they are paused before
//! the disk fills up.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::config::HostConfig;
use crate::vm::Manager;

const GIB: u64 = 1 << 30;
/// How often the disk watchdog checks free space.
pub const WATCHDOG_INTERVAL: Duration = Duration::from_secs(10);

/// Host resources and what running VMs take from them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostInfo {
    pub cores: u32,
    /// vCPUs of running VMs.
    pub vcpus_allotted: u32,
    pub memory_total_mib: u64,
    pub memory_available_mib: u64,
    /// Share of MemTotal that running VMs may use.
    pub memory_budget_mib: u64,
    /// Memory limits of running VMs (guest RAM + QEMU overhead).
    pub memory_used_mib: u64,
    pub disk_free_bytes: u64,
    pub disk_floor_gib: u64,
    pub running_vms: u32,
}

impl std::fmt::Display for HostInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let free = self.memory_budget_mib.saturating_sub(self.memory_used_mib);
        writeln!(
            f,
            "memory  {} MiB budget, {} MiB used, {free} MiB free  (host: {} MiB available of {} MiB)",
            self.memory_budget_mib,
            self.memory_used_mib,
            self.memory_available_mib,
            self.memory_total_mib
        )?;
        writeln!(
            f,
            "disk    {:.1} GiB free, floor {} GiB",
            self.disk_free_bytes as f64 / GIB as f64,
            self.disk_floor_gib
        )?;
        writeln!(
            f,
            "cpu     {} vCPUs allotted to {} running VMs, {} cores",
            self.vcpus_allotted, self.running_vms, self.cores
        )
    }
}

/// What a VM asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ask {
    pub vcpus: u32,
    pub memory_mib: u64,
    pub overhead_mib: u64,
    /// New disk space that may be used (the virtual size, for create).
    pub disk_bytes: u64,
}

/// Decides whether a VM fits. Pure, so every rule is unit-tested.
pub fn admit(host: &HostInfo, ask: &Ask, cfg: &HostConfig) -> Result<()> {
    let keep = cfg.reserved_cores;
    ensure!(
        ask.vcpus + keep <= host.cores,
        "{} vCPUs is too many for a {}-core host (at most {}; {keep} stay with the host)",
        ask.vcpus,
        host.cores,
        host.cores.saturating_sub(keep)
    );
    let left = host.memory_budget_mib.saturating_sub(host.memory_used_mib);
    let want = ask.memory_mib + ask.overhead_mib;
    ensure!(
        want <= left,
        "{want} MiB (guest RAM + QEMU overhead) is over the VM memory budget: {left} MiB of {} MiB left; stop a VM or lower --mem",
        host.memory_budget_mib
    );
    let need = ask.memory_mib + ask.overhead_mib + cfg.reserve_mib;
    ensure!(
        host.memory_available_mib >= need,
        "not enough free host memory: {} MiB available, {need} MiB needed ({} MiB stays reserved for the host)",
        host.memory_available_mib,
        cfg.reserve_mib
    );
    let floor = cfg.disk_floor_gib.saturating_mul(GIB);
    ensure!(
        host.disk_free_bytes >= floor + ask.disk_bytes,
        "not enough disk space: {:.1} GiB free, {:.1} GiB needed ({} GiB floor + new disk)",
        host.disk_free_bytes as f64 / GIB as f64,
        (floor + ask.disk_bytes) as f64 / GIB as f64,
        cfg.disk_floor_gib
    );
    Ok(())
}

/// `MemTotal` and `MemAvailable` from `/proc/meminfo`, in MiB.
fn parse_meminfo(text: &str) -> Result<(u64, u64)> {
    let field = |key: &str| -> Result<u64> {
        let line = text
            .lines()
            .find(|l| l.starts_with(key) && l[key.len()..].starts_with(':'))
            .with_context(|| format!("{key} missing from /proc/meminfo"))?;
        let kib: u64 = line[key.len() + 1..]
            .trim()
            .trim_end_matches("kB")
            .trim()
            .parse()?;
        Ok(kib / 1024)
    };
    Ok((field("MemTotal")?, field("MemAvailable")?))
}

/// Bytes available to unprivileged users on the filesystem of `path`.
pub fn disk_free(path: &Path) -> Result<u64> {
    let st = rustix::fs::statvfs(path)?;
    Ok(st.f_bavail.saturating_mul(st.f_frsize))
}

/// Reads the host's current state. `vms` are (vcpus, memory limit in MiB)
/// of the running VMs; `unfaulted_mib` is memory they may still take, which
/// is subtracted from MemAvailable.
pub fn snapshot(
    data: &Path,
    cfg: &HostConfig,
    vms: &[(u32, u64)],
    unfaulted_mib: u64,
) -> Result<HostInfo> {
    let (total, available) = parse_meminfo(&std::fs::read_to_string("/proc/meminfo")?)?;
    let cores = std::thread::available_parallelism()?.get() as u32;
    Ok(HostInfo {
        cores,
        vcpus_allotted: vms.iter().map(|v| v.0).sum(),
        memory_total_mib: total,
        memory_available_mib: available.saturating_sub(unfaulted_mib),
        memory_budget_mib: total * cfg.memory_budget_pct / 100,
        memory_used_mib: vms.iter().map(|v| v.1).sum(),
        disk_free_bytes: disk_free(data)?,
        disk_floor_gib: cfg.disk_floor_gib,
        running_vms: vms.len() as u32,
    })
}

/// Whether a snapshot fits: `need_bytes` (the guest RAM it stores; 0 for
/// disk only) must fit above the floor. Checked before every snapshot.
pub fn check_snapshot_space(free_bytes: u64, floor_gib: u64, need_bytes: u64) -> Result<()> {
    let need = floor_gib.saturating_mul(GIB).saturating_add(need_bytes);
    ensure!(
        free_bytes >= need,
        "not enough disk space for a snapshot: {:.1} GiB free, {:.1} GiB needed ({floor_gib} GiB floor + {:.1} GiB of guest RAM)",
        free_bytes as f64 / GIB as f64,
        need as f64 / GIB as f64,
        need_bytes as f64 / GIB as f64
    );
    Ok(())
}

/// Whether free space is below the floor.
pub fn below_floor(free_bytes: u64, floor_gib: u64) -> bool {
    free_bytes < floor_gib.saturating_mul(GIB)
}

/// Every [`WATCHDOG_INTERVAL`]: if the data filesystem is below the floor,
/// pause every running VM. `werror=stop` on the disks covers ENOSPC between
/// checks. A human resumes with `stallo resume <vm>` once space is back.
pub async fn watchdog(manager: Arc<Manager>) {
    let mut tick = tokio::time::interval(WATCHDOG_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let floor = manager.config.host.disk_floor_gib;
        let free = match disk_free(&manager.paths.data) {
            Ok(f) => f,
            Err(e) => {
                tracing::error!("disk watchdog cannot read free space: {e:#}");
                continue;
            }
        };
        if !below_floor(free, floor) {
            continue;
        }
        for vm in manager.all_running() {
            match vm.pause_disk_full().await {
                Ok(true) => tracing::warn!(
                    "{}: paused, data disk below the {floor} GiB floor",
                    vm.config.name
                ),
                Ok(false) => {}
                Err(e) => tracing::error!("{}: pause failed: {e:#}", vm.config.name),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host() -> HostInfo {
        HostInfo {
            cores: 16,
            vcpus_allotted: 0,
            memory_total_mib: 28 * 1024,
            memory_available_mib: 20 * 1024,
            memory_budget_mib: 14 * 1024,
            memory_used_mib: 0,
            disk_free_bytes: 500 * GIB,
            disk_floor_gib: 20,
            running_vms: 0,
        }
    }

    fn ask() -> Ask {
        Ask {
            vcpus: 2,
            memory_mib: 2048,
            overhead_mib: 256,
            disk_bytes: 20 * GIB,
        }
    }

    #[test]
    fn admits_a_normal_vm() {
        admit(&host(), &ask(), &HostConfig::default()).unwrap();
    }

    #[test]
    fn refuses_over_budget() {
        let h = HostInfo {
            memory_used_mib: 13 * 1024,
            ..host()
        };
        let err = admit(&h, &ask(), &HostConfig::default()).unwrap_err();
        assert!(err.to_string().contains("budget"), "{err}");
    }

    #[test]
    fn refuses_when_host_memory_is_short() {
        let h = HostInfo {
            memory_available_mib: 5 * 1024,
            ..host()
        };
        let err = admit(&h, &ask(), &HostConfig::default()).unwrap_err();
        assert!(err.to_string().contains("free host memory"), "{err}");
    }

    #[test]
    fn refuses_too_many_vcpus_and_little_disk() {
        let cfg = HostConfig::default();
        let a = Ask { vcpus: 15, ..ask() };
        assert!(admit(&host(), &a, &cfg).is_err());
        let a = Ask { vcpus: 14, ..ask() };
        assert!(admit(&host(), &a, &cfg).is_ok());
        let h = HostInfo {
            disk_free_bytes: 39 * GIB,
            ..host()
        };
        let err = admit(&h, &ask(), &cfg).unwrap_err();
        assert!(err.to_string().contains("disk"), "{err}");
    }

    #[test]
    fn boundaries_are_inclusive() {
        let cfg = HostConfig::default();
        let a = ask();
        let exact = HostInfo {
            memory_available_mib: a.memory_mib + a.overhead_mib + cfg.reserve_mib,
            disk_free_bytes: cfg.disk_floor_gib * GIB + a.disk_bytes,
            memory_used_mib: host().memory_budget_mib - a.memory_mib - a.overhead_mib,
            ..host()
        };
        admit(&exact, &a, &cfg).unwrap();
        let tiny = HostInfo { cores: 2, ..host() };
        let err = admit(&tiny, &Ask { vcpus: 1, ..a }, &cfg).unwrap_err();
        assert!(err.to_string().contains("vCPUs"), "{err}");
        // A lab VM with 2 cores can run a 1-vCPU guest if told to.
        let lab = HostConfig {
            reserved_cores: 1,
            ..cfg.clone()
        };
        admit(&tiny, &Ask { vcpus: 1, ..a }, &lab).unwrap();
        assert!(admit(&tiny, &Ask { vcpus: 2, ..a }, &lab).is_err());
    }

    #[test]
    fn meminfo() {
        let text = "MemTotal:       29313300 kB\nMemFree:  1 kB\nMemAvailable:   24117248 kB\n";
        assert_eq!(parse_meminfo(text).unwrap(), (28626, 23552));
        assert!(parse_meminfo("MemTotal: 1 kB\n").is_err());
    }

    /// S13 (unit part): the watchdog trigger.
    #[test]
    fn floor() {
        assert!(below_floor(19 * GIB, 20));
        assert!(!below_floor(20 * GIB, 20));
    }

    #[test]
    fn snapshot_space() {
        assert!(check_snapshot_space(22 * GIB, 20, 2 * GIB).is_ok());
        let err = check_snapshot_space(22 * GIB - 1, 20, 2 * GIB).unwrap_err();
        assert!(err.to_string().contains("22.0 GiB needed"), "{err}");
        assert!(check_snapshot_space(20 * GIB, 20, 0).is_ok());
        assert!(check_snapshot_space(u64::MAX, u64::MAX, u64::MAX).is_ok());
    }

    #[test]
    fn real_host_snapshot() {
        let h = snapshot(Path::new("/"), &HostConfig::default(), &[(2, 2048)], 0).unwrap();
        assert!(h.cores >= 1 && h.memory_total_mib > 0 && h.disk_free_bytes > 0);
        assert_eq!(h.memory_used_mib, 2048);
    }
}
