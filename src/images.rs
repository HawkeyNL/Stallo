//! Image catalog and verified downloads.
//!
//! A cloud image is used only after: the signature on the checksum list
//! (detached or clearsigned) verifies against the catalog's keyring (`gpgv`)
//! and comes from the pinned signing key, the image's SHA-256 (computed
//! here) matches its line in the signed text, and `qemu-img info` shows a
//! plain qcow2 with no backing file and no external data file. A `moving`
//! checksum list's signature must be at most [`MAX_SUMS_SIG_AGE_DAYS`] old.
//! With `signed-image`, a detached signature over the image itself replaces
//! the checksum list, and it must be at most [`MAX_SIG_AGE_DAYS`] old. With
//! `pinned`, for upstreams that sign nothing, the image's SHA-512 is in the
//! catalog itself, so an update needs a new Stallo release. Cached
//! images are read-only and never replaced, because VM disks are overlays on
//! them; `stallo images rm` deletes one that no VM uses.
//!
//! An installer ISO (`kind = "iso"`) is verified the same way, up to its
//! SHA-256; it is untrusted guest input that only QEMU reads, so nothing on
//! the host mounts or parses it (no `qemu-img`). It is cached as
//! `<id>.iso`, read-only.
//!
//! Keyrings are host files (Ubuntu's, from its keyring packages) or
//! vendored in `catalog/keys/` and compiled in.
//!
//! Guest-agent packages come from apt in a private root that trusts only the
//! catalog's sources and keyring, never the host's apt configuration.
//!
//! TLS and OpenPGP stay with `curl`, `gpgv` and apt, which Ubuntu patches;
//! every subprocess gets fixed arguments, never a shell.
//!
//! Callers serialise pulls (the daemon holds one lock for all of them).

use std::fs;
use std::io::Read;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256, Sha512};
use tokio::process::Command;

use crate::config::{NetProfile, validate_image_id};
use crate::paths::{Paths, ensure_private_dir, safe_remove};
use crate::run_tool;

/// One catalog entry (`catalog/<id>.toml`, compiled in). The format is
/// flat: which fields apply depends on `trust` and `agent`, and
/// [`CatalogEntry::validate`] checks the combinations.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogEntry {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub kind: Kind,
    pub os: Os,
    pub firmware: Firmware,
    /// The qcow2 image or installer ISO (HTTPS).
    pub url: String,
    /// Largest image download accepted, in bytes.
    pub max_size: u64,
    pub trust: Trust,
    /// The checksum list (`signed-sums`).
    pub sums_url: Option<String>,
    /// The detached signature over the checksum list or the image; empty
    /// for a clearsigned checksum list.
    pub sig_url: Option<String>,
    pub sums_format: Option<SumsFormat>,
    /// The OpenPGP keyring that holds `signing_key`: an absolute host path,
    /// or the name of a keyring in `catalog/keys/`.
    pub keyring: Option<String>,
    /// Fingerprint of the primary key that must sign.
    pub signing_key: Option<String>,
    /// SHA-512 of the image (`pinned`).
    pub sha512: Option<String>,
    pub agent: Agent,
    /// Packages the guest needs for the guest agent but lacks (`deb`).
    #[serde(default)]
    pub debs: Vec<String>,
    /// apt sources for `debs`: `<https uri> <suite> <components...>`.
    #[serde(default)]
    pub deb_sources: Vec<String>,
    /// The only keyring apt trusts for `deb_sources`: an absolute host
    /// path, or the name of a keyring in `catalog/keys/`.
    pub deb_keyring: Option<String>,
    /// Make the guest agent's SELinux domain permissive (see seed.rs): for
    /// guests where SELinux confines it, such as Fedora.
    #[serde(default)]
    pub qga_permissive: bool,
    /// The `internet` profile was verified with this image. Others refuse
    /// it, since the guest's network config may not match its NIC.
    #[serde(default)]
    pub internet: bool,
    /// `url` and `sums_url` move to each new build (`current/`): the
    /// signature on the checksum list must then be at most
    /// [`MAX_SUMS_SIG_AGE_DAYS`] old. Release-pinned files never change, so
    /// their old signatures stay valid. (`signed-image` always checks it.)
    #[serde(default)]
    pub moving: bool,
}

/// What the catalog entry downloads.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    /// A qcow2 cloud image: VM disks are overlays on it, and the seed ISO
    /// sets the guest up.
    #[default]
    CloudImage,
    /// An installer ISO, attached as a read-only CD-ROM to a blank disk. The
    /// user installs over VNC.
    Iso,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Os {
    Linux,
    Windows,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Firmware {
    /// OVMF with Secure Boot and Microsoft's keys enrolled.
    SecureBoot,
    /// OVMF without Secure Boot, for images with an unsigned boot chain.
    Uefi,
}

/// How an image is verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Trust {
    /// A checksum list with a detached OpenPGP signature.
    SignedSums,
    /// A detached OpenPGP signature over the image itself.
    SignedImage,
    /// A SHA-512 in the catalog, for upstreams that sign nothing.
    Pinned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SumsFormat {
    /// `<hex> *<name>` lines (`sha256sum`).
    Gnu,
    /// `SHA256 (<name>) = <hex>` lines.
    Bsd,
}

/// How the guest gets its guest agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Agent {
    /// The image ships it.
    Preinstalled,
    /// `.deb` packages on the seed ISO.
    Deb,
    /// None until the user installs one: installer ISOs, which get no seed.
    Manual,
}

impl CatalogEntry {
    /// Checks the field combinations, then refuses what this version cannot
    /// handle yet.
    pub fn validate(&self) -> Result<()> {
        validate_image_id(&self.id)?;
        let id = &self.id;
        let https = |u: &str| u.starts_with("https://") && !u.contains(char::is_whitespace);
        ensure!(
            https(&self.url) && !self.url.ends_with('/'),
            "{id}: url must be an https:// file URL"
        );
        if let Some(u) = &self.sums_url {
            ensure!(https(u), "{id}: {u:?} is not an https:// URL");
        }
        // An empty sig_url means a clearsigned checksum list.
        if let Some(u) = &self.sig_url {
            ensure!(
                https(u) || (u.is_empty() && self.trust == Trust::SignedSums),
                "{id}: {u:?} is not an https:// URL"
            );
        }
        let vendored = |k: &str| KEYS.iter().any(|(name, _)| *name == k);
        if let Some(k) = &self.keyring {
            ensure!(
                (k.starts_with('/') && !k.contains(char::is_whitespace)) || vendored(k),
                "{id}: keyring {k:?} is neither an absolute path nor in catalog/keys/"
            );
        }
        if let Some(k) = &self.signing_key {
            ensure!(
                k.len() == 40 && k.bytes().all(|c| matches!(c, b'0'..=b'9' | b'A'..=b'F')),
                "{id}: signing_key must be a fingerprint of 40 upper-case hex digits"
            );
        }
        let keys = self.keyring.is_some() && self.signing_key.is_some();
        match self.trust {
            Trust::SignedSums => ensure!(
                keys && self.sums_url.is_some()
                    && self.sig_url.is_some()
                    && self.sums_format.is_some()
                    && self.sha512.is_none(),
                "{id}: signed-sums needs sums_url, sig_url, sums_format, keyring and signing_key, and no sha512"
            ),
            Trust::SignedImage => ensure!(
                keys && self.sig_url.is_some()
                    && self.sums_url.is_none()
                    && self.sums_format.is_none()
                    && self.sha512.is_none(),
                "{id}: signed-image needs sig_url, keyring and signing_key, and no sums or sha512"
            ),
            Trust::Pinned => ensure!(
                self.sha512.as_deref().is_some_and(|h| {
                    h.len() == 128 && h.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
                }) && self.keyring.is_none()
                    && self.signing_key.is_none()
                    && self.sums_url.is_none()
                    && self.sig_url.is_none()
                    && self.sums_format.is_none(),
                "{id}: pinned needs a sha512 of 128 lower-case hex digits and no keys, sums or signature"
            ),
        }
        match self.agent {
            Agent::Deb => ensure!(
                !self.debs.is_empty() && !self.deb_sources.is_empty() && self.deb_keyring.is_some(),
                "{id}: agent \"deb\" needs debs, deb_sources and deb_keyring"
            ),
            Agent::Preinstalled | Agent::Manual => ensure!(
                self.debs.is_empty() && self.deb_sources.is_empty() && self.deb_keyring.is_none(),
                "{id}: a preinstalled or manual agent takes no debs, deb_sources or deb_keyring"
            ),
        }
        ensure!(
            (self.kind == Kind::Iso) == (self.agent == Agent::Manual),
            "{id}: an ISO, and only an ISO, has agent \"manual\""
        );
        // An ISO gets no seed (so nothing for qga_permissive to do), and the
        // internet profile is not verified with any installer.
        ensure!(
            self.kind == Kind::CloudImage
                || (self.trust == Trust::SignedSums
                    && self.url.ends_with(".iso")
                    && !self.qga_permissive
                    && !self.internet),
            "{id}: an ISO needs signed-sums and a .iso url, and takes no qga_permissive or internet"
        );
        // Both go into sources.list lines: no options, comments or breaks.
        let plain = |w: &str| {
            !w.is_empty()
                && w.bytes()
                    .all(|c| c.is_ascii_graphic() && !b"[]#".contains(&c))
        };
        for src in &self.deb_sources {
            let words: Vec<&str> = src.split(' ').collect();
            ensure!(
                words.len() >= 3 && https(words[0]) && words.iter().all(|w| plain(w)),
                "{id}: deb source {src:?} is not `<https uri> <suite> <components>`"
            );
        }
        // `signed-by=` takes a comma-separated list: one keyring file only
        // (apt_root checks the path a vendored name resolves to as well).
        if let Some(k) = &self.deb_keyring {
            ensure!(
                (k.starts_with('/') || vendored(k))
                    && plain(k)
                    && !k.contains(',')
                    && (k.ends_with(".gpg") || k.ends_with(".pgp")),
                "{id}: deb_keyring must be one absolute .gpg or .pgp path, or a keyring in catalog/keys/"
            );
        }
        // Package names become apt arguments: no options.
        for d in &self.debs {
            ensure!(
                d.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
                    && d.bytes().all(|c| {
                        c.is_ascii_lowercase() || c.is_ascii_digit() || b"+-.".contains(&c)
                    }),
                "{id}: invalid package name {d:?}"
            );
        }
        ensure!(
            !self.moving || self.trust == Trust::SignedSums,
            "{id}: moving applies to signed-sums only (signed-image always checks the signature age)"
        );
        ensure!(
            self.os == Os::Linux,
            "{id}: not supported yet: only Linux images"
        );
        Ok(())
    }

    /// Refuses the `internet` profile unless it was verified with this
    /// image.
    pub fn check_net(&self, net: NetProfile) -> Result<()> {
        ensure!(
            net == NetProfile::Offline || self.internet,
            "{}: the internet profile is not supported for this image yet",
            self.id
        );
        Ok(())
    }

    /// The image's file name, as listed in the checksums.
    fn file(&self) -> &str {
        self.url.rsplit('/').next().unwrap_or_default()
    }
}

const CATALOG: &[&str] = &[
    include_str!("../catalog/ubuntu-26.04.toml"),
    include_str!("../catalog/ubuntu-24.04.toml"),
    include_str!("../catalog/fedora-44.toml"),
    include_str!("../catalog/arch.toml"),
    include_str!("../catalog/debian-13.toml"),
    include_str!("../catalog/ubuntu-26.04-desktop.toml"),
    include_str!("../catalog/fedora-44-workstation.toml"),
];

/// OpenPGP keyrings (binary) that catalog entries name in `keyring` or
/// `deb_keyring`. A unit test pins the fingerprints in each.
const KEYS: &[(&str, &[u8])] = &[
    ("fedora.gpg", include_bytes!("../catalog/keys/fedora.gpg")),
    (
        "arch-boxes.gpg",
        include_bytes!("../catalog/keys/arch-boxes.gpg"),
    ),
    (
        "debian-archive-trixie.gpg",
        include_bytes!("../catalog/keys/debian-archive-trixie.gpg"),
    ),
];

/// The oldest signature `signed-image` accepts. Its URLs move to each new
/// build (Arch publishes one every two weeks), so an older signature means
/// a stale or replaying mirror. 45 days leaves room for two missed builds.
///
/// A detached signature does not name the file: within this window, a
/// mirror could serve any image the same key signed (an older build, or
/// another image type) under the catalog's URL. TLS to the catalog's host
/// and this age limit are what bound that.
pub const MAX_SIG_AGE_DAYS: u64 = 45;

/// The oldest signature a `moving` checksum list accepts (Ubuntu's
/// `current/`, rebuilt every week or few, but irregularly): an older one
/// means a stale or replaying mirror, or an upstream that stopped
/// rebuilding.
pub const MAX_SUMS_SIG_AGE_DAYS: u64 = 90;

/// All catalog entries.
pub fn catalog() -> Vec<CatalogEntry> {
    CATALOG
        .iter()
        .map(|text| {
            let entry: CatalogEntry = toml::from_str(text).expect("built-in catalog parses");
            entry.validate().expect("built-in catalog is valid");
            entry
        })
        .collect()
}

/// The catalog entry for `id`.
pub fn find(id: &str) -> Result<CatalogEntry> {
    validate_image_id(id)?;
    catalog()
        .into_iter()
        .find(|e| e.id == id)
        .with_context(|| format!("unknown image {id:?}; see `stallo images`"))
}

/// `<data>/images/<id>.qcow2`.
pub fn image_path(paths: &Paths, id: &str) -> PathBuf {
    paths.images_dir().join(format!("{id}.qcow2"))
}

/// `<data>/images/<id>.iso`.
pub fn iso_path(paths: &Paths, id: &str) -> PathBuf {
    paths.images_dir().join(format!("{id}.iso"))
}

/// Where a pull of `entry` caches its image or ISO.
pub fn cached_path(paths: &Paths, entry: &CatalogEntry) -> PathBuf {
    match entry.kind {
        Kind::CloudImage => image_path(paths, &entry.id),
        Kind::Iso => iso_path(paths, &entry.id),
    }
}

/// `<data>/images/<id>.debs/`.
pub fn debs_dir(paths: &Paths, id: &str) -> PathBuf {
    paths.images_dir().join(format!("{id}.debs"))
}

/// `<data>/images/<id>.toml`: what the pull recorded (see [`Pulled`]).
fn record_path(paths: &Paths, id: &str) -> PathBuf {
    paths.images_dir().join(format!("{id}.toml"))
}

/// What a pull recorded next to the image. Informational: images pulled by
/// older versions have none.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pulled {
    /// SHA-256 of the cached image file.
    pub sha256: String,
    /// The signature's date (`YYYY-MM-DD`, UTC), if the image was signed.
    pub sig_date: Option<String>,
    /// Seconds since the epoch.
    pub pulled_at: u64,
}

/// The record of a pull of `id`, if there is a readable one.
pub fn pulled(paths: &Paths, id: &str) -> Option<Pulled> {
    toml::from_str(&fs::read_to_string(record_path(paths, id)).ok()?).ok()
}

/// Whether the image and its guest-agent packages (if any) are cached.
pub fn is_cached(paths: &Paths, entry: &CatalogEntry) -> bool {
    cached_path(paths, entry).is_file()
        && (entry.agent != Agent::Deb || debs_dir(paths, &entry.id).is_dir())
}

/// Refuses an image that is not cached: agents create VMs only from
/// images a human pulled.
pub fn ensure_pulled(paths: &Paths, id: &str) -> Result<()> {
    let entry = find(id)?;
    ensure!(
        is_cached(paths, &entry),
        "image {id} not pulled; a human runs `stallo images pull {id}`"
    );
    Ok(())
}

/// Guest-agent packages that older versions cached per Ubuntu release
/// (`debs/<release>/`). They came from the host's apt sources, so they are
/// only a fallback for a host that cannot fetch new ones.
///
/// With `keep`, moves them to `<id>.debs/` and returns whether it did;
/// otherwise deletes them. Either way drops an old partial download.
fn old_debs(paths: &Paths, id: &str, keep: bool) -> Result<bool> {
    let root = paths.images_dir();
    let Some(release) = id.strip_prefix("ubuntu-") else {
        return Ok(false);
    };
    if !root.is_dir() {
        return Ok(false);
    }
    safe_remove(&root, &root.join(format!(".partial-debs-{release}")))?;
    let old = root.join("debs").join(release);
    let moved = keep && old.is_dir() && !debs_dir(paths, id).exists();
    if moved {
        fs::rename(&old, debs_dir(paths, id))?;
    } else {
        safe_remove(&root, &old)?;
    }
    fs::File::open(&root)?.sync_all()?;
    // Goes only once it is empty.
    let _ = fs::remove_dir(root.join("debs"));
    Ok(moved)
}

/// Deletes the cached image `id`, its record, its guest-agent packages and
/// what failed pulls left behind; returns whether there was anything.
/// Symlinks are refused, never followed. The caller makes sure no VM disk
/// backs onto the image and that no pull runs.
pub fn remove(paths: &Paths, id: &str) -> Result<bool> {
    validate_image_id(id)?;
    let root = paths.images_dir();
    if !root.is_dir() {
        return Ok(false);
    }
    let mut found = false;
    // The image first: without it nothing counts as cached.
    for name in [
        format!("{id}.qcow2"),
        format!("{id}.iso"),
        format!("{id}.toml"),
        format!("{id}.debs"),
        format!(".partial-{id}"),
        format!(".partial-debs-{id}"),
    ] {
        let path = root.join(name);
        if fs::symlink_metadata(&path).is_ok() {
            safe_remove(&root, &path)?;
            found = true;
        }
    }
    old_debs(paths, id, false)?;
    fs::File::open(&root)?.sync_all()?;
    Ok(found)
}

/// Bytes a pull of `entry` may resume: the largest partial image download
/// (at most `max_size`). Other partial files may be from an older upstream
/// build and are not resumed, but they already count as used space.
pub fn resumable_bytes(paths: &Paths, entry: &CatalogEntry) -> u64 {
    let work = paths.images_dir().join(format!(".partial-{}", entry.id));
    let Ok(dir) = fs::read_dir(work) else {
        return 0;
    };
    dir.filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_str().is_some_and(|n| n.ends_with(".part")))
        // DirEntry::metadata does not follow symlinks.
        .filter_map(|e| e.metadata().ok().filter(|m| m.is_file()))
        .map(|m| m.len().min(entry.max_size))
        .max()
        .unwrap_or(0)
}

/// The backing file name in the header of the qcow2 file `disk`, or `None`
/// if it has none or does not exist. Read from the header directly: a VM's
/// disk is written by its QEMU, so `qemu-img` never opens it.
pub fn backing_file(disk: &Path) -> Result<Option<String>> {
    use std::os::unix::fs::FileExt;
    let f = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(disk)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("cannot open {}", disk.display())),
    };
    let mut header = [0; 20];
    f.read_exact_at(&mut header, 0)
        .with_context(|| format!("{} has no qcow2 header", disk.display()))?;
    ensure!(
        header[..4] == *b"QFI\xfb",
        "{} is not a qcow2 file",
        disk.display()
    );
    let offset = u64::from_be_bytes(header[8..16].try_into()?);
    let len = u32::from_be_bytes(header[16..20].try_into()?);
    if offset == 0 {
        return Ok(None);
    }
    // QEMU's limit for the name.
    ensure!(
        (1..=1023).contains(&len),
        "{}: bad backing file name",
        disk.display()
    );
    let mut name = vec![0; len as usize];
    f.read_exact_at(&mut name, offset)
        .with_context(|| format!("{}: bad backing file name", disk.display()))?;
    Ok(Some(String::from_utf8_lossy(&name).into_owned()))
}

/// Downloads and verifies whatever of `entry` is not cached yet.
pub async fn pull(paths: &Paths, entry: &CatalogEntry) -> Result<()> {
    ensure_private_dir(&paths.images_dir())?;
    if !cached_path(paths, entry).is_file() {
        pull_image(paths, entry).await?;
    }
    if entry.agent == Agent::Deb && !debs_dir(paths, &entry.id).is_dir() {
        // An older cache is used only when fresh packages cannot be
        // fetched (no network): it is no worse than before the upgrade.
        if let Err(e) = pull_debs(paths, entry).await {
            if !old_debs(paths, &entry.id, true)? {
                return Err(e);
            }
            tracing::warn!(
                "{}: using guest-agent packages cached by an older version: {e:#}",
                entry.id
            );
            return Ok(());
        }
    }
    old_debs(paths, &entry.id, false)?;
    Ok(())
}

async fn pull_image(paths: &Paths, entry: &CatalogEntry) -> Result<()> {
    let root = paths.images_dir();
    let work = root.join(format!(".partial-{}", entry.id));
    ensure_private_dir(&work)?;
    let (image, validsig) = match entry.trust {
        Trust::SignedSums => fetch_signed_sums(paths, entry, &work).await?,
        Trust::SignedImage => fetch_signed_image(paths, entry, &work).await?,
        Trust::Pinned => {
            let expected = field(&entry.sha512)?;
            let image = fetch_hashed::<Sha512>(paths, entry, &work, &expected).await?;
            (image, vec![])
        }
    };
    // An ISO is only ever read by QEMU: its SHA-256 is all the host checks.
    if entry.kind == Kind::CloudImage
        && let Err(e) = check_image(&image).await
    {
        // Otherwise the next pull would find the same file complete.
        safe_remove(&root, &image)?;
        return Err(e);
    }

    fs::set_permissions(&image, fs::Permissions::from_mode(0o444))?;
    fs::File::open(&image)?.sync_all()?;
    let record = Pulled {
        sha256: hash_file::<Sha256>(&image).await?,
        sig_date: sig_date(&validsig),
        pulled_at: now_secs()?,
    };
    let tmp = work.join("record.toml");
    fs::write(&tmp, toml::to_string(&record)?)?;
    fs::File::open(&tmp)?.sync_all()?;
    fs::rename(&tmp, record_path(paths, &entry.id))?;
    // A hard link fails if the target exists: a cached base image is never
    // replaced, because VM disks are overlays on it (and VMs boot from a
    // cached ISO).
    fs::hard_link(&image, cached_path(paths, entry))?;
    fs::File::open(&root)?.sync_all()?;
    safe_remove(&root, &work)?;
    Ok(())
}

/// The date of a signature (VALIDSIG field 1, `YYYY-MM-DD`), if any.
fn sig_date(validsig: &[String]) -> Option<String> {
    validsig
        .get(1)
        .filter(|d| d.len() == 10 && d.bytes().all(|c| c.is_ascii_digit() || c == b'-'))
        .cloned()
}

/// `validate` guarantees the fields each trust needs.
fn field(f: &Option<String>) -> Result<String> {
    f.clone().context("incomplete catalog entry")
}

/// Downloads the image into `work` and checks it against the signed
/// checksum list; returns its path and the signature's VALIDSIG fields. A
/// `moving` list's signature must be recent (see [`check_sig_age`]).
async fn fetch_signed_sums(
    paths: &Paths,
    entry: &CatalogEntry,
    work: &Path,
) -> Result<(PathBuf, Vec<String>)> {
    let root = paths.images_dir();
    let sums = work.join("SHA256SUMS");
    let sig = work.join("SHA256SUMS.gpg");
    let signed = work.join("SHA256SUMS.signed");
    for f in [&sums, &sig, &signed] {
        safe_remove(&root, f)?;
    }
    download(&field(&entry.sums_url)?, &sums, 1 << 20, false).await?;
    let sig_url = field(&entry.sig_url)?;
    let sig = if sig_url.is_empty() {
        None
    } else {
        download(&sig_url, &sig, 1 << 20, false).await?;
        Some(sig.as_path())
    };
    let keyring = keyring_path(paths, &field(&entry.keyring)?)?;
    let (text, validsig) = signed_text(&keyring, &field(&entry.signing_key)?, &sums, sig, &signed)
        .await
        .context("signature check of the checksum list failed")?;
    if entry.moving {
        now_secs()
            .and_then(|now| check_sig_age(&validsig, now, MAX_SUMS_SIG_AGE_DAYS))
            .context("signature check of the checksum list failed")?;
    }
    let format = entry.sums_format.context("incomplete catalog entry")?;
    let expected = expected_sha256(&text, entry.file(), format)?;
    let image = fetch_hashed::<Sha256>(paths, entry, work, &expected).await?;
    Ok((image, validsig))
}

/// Downloads the image into `work` and checks it against `expected`, its
/// hash in lower-case hex; returns its path.
///
/// Resumes a partial download, and skips it if a complete file is already
/// there. The name carries the expected hash, so a partial download of
/// another file (an older upstream image, a different pin) is never resumed
/// into this one. A mismatch deletes the file and fails: the next pull
/// starts from scratch.
async fn fetch_hashed<D: Digest + 'static>(
    paths: &Paths,
    entry: &CatalogEntry,
    work: &Path,
    expected: &str,
) -> Result<PathBuf> {
    let root = paths.images_dir();
    let image = work.join(format!("{expected}.part"));
    // curl's size cap counts only what it fetches, not the part it resumes.
    drop_oversized(&root, &image, entry.max_size)?;
    if !image.exists() || hash_file::<D>(&image).await? != expected {
        tracing::info!("downloading {}", entry.url);
        download(&entry.url, &image, entry.max_size, true).await?;
        ensure!(
            !drop_oversized(&root, &image, entry.max_size)?,
            "{} is larger than {} bytes",
            entry.file(),
            entry.max_size
        );
        check_hash::<D>(&root, &image, expected)
            .await
            .with_context(|| format!("{} is not the expected image", entry.file()))?;
    }
    Ok(image)
}

/// Removes `file` (inside `root`) if it is there but not a regular file or
/// larger than `max_size`; returns whether it did. A symlink is an error
/// (`safe_remove` refuses it).
fn drop_oversized(root: &Path, file: &Path, max_size: u64) -> Result<bool> {
    let drop = match fs::symlink_metadata(file) {
        Ok(m) => !m.is_file() || m.len() > max_size,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(e.into()),
    };
    if drop {
        safe_remove(root, file)?;
    }
    Ok(drop)
}

/// Checks the hash of `file` (inside `root`) against `expected`; deletes
/// the file if it differs.
async fn check_hash<D: Digest + 'static>(root: &Path, file: &Path, expected: &str) -> Result<()> {
    let actual = hash_file::<D>(file).await?;
    if actual != expected {
        safe_remove(root, file)?;
        bail!(
            "hash mismatch for {}: got {actual}, want {expected}",
            file.display()
        );
    }
    Ok(())
}

/// Downloads the image into `work` and checks the detached signature over
/// it; returns its path and the signature's VALIDSIG fields.
///
/// No hash is known before the download, so the partial file is named
/// after the URL: a partial download from another catalog URL is never
/// resumed into this one. A moving URL can still serve a newer build
/// behind a partial download, and a mirror can be caught between image and
/// signature while it publishes: either fails gpgv, which deletes both and
/// tries once more from scratch. So does a failed resume (a mirror that
/// ignores ranges). A failed fresh download keeps the partial file for the
/// next pull to resume. A valid signature that is too old, or of the wrong
/// kind, deletes both and fails at once: a retry would get the same.
async fn fetch_signed_image(
    paths: &Paths,
    entry: &CatalogEntry,
    work: &Path,
) -> Result<(PathBuf, Vec<String>)> {
    let root = paths.images_dir();
    let key = url_key(&entry.url);
    let image = work.join(format!("{key}.part"));
    let sig = work.join(format!("{key}.sig"));
    let keyring = keyring_path(paths, &field(&entry.keyring)?)?;
    let fingerprint = field(&entry.signing_key)?;
    let mut retried = false;
    loop {
        safe_remove(&root, &sig)?;
        download(&field(&entry.sig_url)?, &sig, 1 << 20, false).await?;
        tracing::info!("downloading {}", entry.url);
        let resumed = image.exists();
        // A complete file is not downloaded again (curl takes the server's
        // "range not satisfiable" as done).
        if let Err(e) = download(&entry.url, &image, entry.max_size, true).await {
            if !resumed || retried {
                return Err(e.context(format!(
                    "a partial download stays in {} for the next pull; remove it to start over",
                    work.display()
                )));
            }
            tracing::warn!("{e:#}; downloading once more from scratch");
            safe_remove(&root, &image)?;
            retried = true;
            continue;
        }
        let context = || format!("signature check of {} failed", entry.url);
        let checked = match gpgv(&keyring, &fingerprint, &[&sig, &image], 600).await {
            Ok(validsig) => now_secs()
                .and_then(|now| check_image_sig(&validsig, now))
                .map(|()| validsig)
                .with_context(context),
            Err(e) if !retried => {
                tracing::warn!("{:#}; downloading once more", e.context(context()));
                safe_remove(&root, &image)?;
                retried = true;
                continue;
            }
            Err(e) => Err(e).with_context(context),
        };
        if checked.is_err() {
            safe_remove(&root, &image)?;
            safe_remove(&root, &sig)?;
        }
        return checked.map(|validsig| (image, validsig));
    }
}

/// Names partial downloads after their URL (SHA-256, hex).
fn url_key(url: &str) -> String {
    Sha256::digest(url.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn now_secs() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("the host clock is before 1970")?
        .as_secs())
}

/// Checks the VALIDSIG fields (see [`check_gpg_status`]) of a signature
/// over an image: a binary document signature (class 00) with SHA-256 or
/// SHA-512 (hash algorithms 8 and 10), at most [`MAX_SIG_AGE_DAYS`] old
/// ([`check_sig_age`]).
fn check_image_sig(validsig: &[String], now: u64) -> Result<()> {
    let field = |i: usize| validsig.get(i).map_or("", String::as_str);
    ensure!(
        field(8) == "00" && matches!(field(7), "8" | "10"),
        "not a binary SHA-256 or SHA-512 signature (class {:?}, hash {:?})",
        field(8),
        field(7)
    );
    check_sig_age(validsig, now, MAX_SIG_AGE_DAYS)
}

/// Checks that a signature (its VALIDSIG fields) was made at most
/// `max_days` before `now` and not more than a day after it (clock skew).
/// Times are seconds since the epoch.
fn check_sig_age(validsig: &[String], now: u64, max_days: u64) -> Result<()> {
    let field = |i: usize| validsig.get(i).map_or("", String::as_str);
    let created: u64 = field(2)
        .parse()
        .context("gpgv gave no signature time in seconds")?;
    ensure!(
        created <= now + 86_400,
        "the signature is from the future: check the host clock"
    );
    let days = now.saturating_sub(created) / 86_400;
    ensure!(
        days <= max_days,
        "the signature is {days} days old (at most {max_days}): the mirror looks stale, or upstream has not rebuilt in {days} days"
    );
    Ok(())
}

/// Downloads `debs` with apt in a private root (see [`apt_root`]). apt
/// checks every package against the signed indexes; no root is needed.
async fn pull_debs(paths: &Paths, entry: &CatalogEntry) -> Result<()> {
    let root = paths.images_dir();
    let work = root.join(format!(".partial-debs-{}", entry.id));
    safe_remove(&root, &work)?;
    let result = fetch_debs(paths, entry, &work).await;
    // apt's indexes take about 90 MB: never leave them behind.
    safe_remove(&root, &work)?;
    result
}

async fn fetch_debs(paths: &Paths, entry: &CatalogEntry, work: &Path) -> Result<()> {
    ensure_private_dir(work)?;
    let keyring = keyring_path(
        paths,
        entry.deb_keyring.as_deref().context("no deb_keyring")?,
    )?;
    let conf = apt_root(work, entry, &keyring)?;
    let debs = work.join("debs");
    let apt = |args: Vec<String>| {
        let mut cmd = Command::new("apt-get");
        cmd.env("APT_CONFIG", &conf)
            .arg("-q")
            .args(args)
            .current_dir(&debs);
        async move { run_tool(&mut cmd, Duration::from_secs(600)).await }
    };
    apt(vec!["update".into()])
        .await
        .context("apt-get update for the guest-agent packages failed")?;
    // The guest image is amd64, whatever the host architecture.
    let mut args = vec!["download".to_owned()];
    args.extend(entry.debs.iter().map(|d| format!("{d}:amd64")));
    apt(args)
        .await
        .context("apt-get download of the guest-agent packages failed")?;
    for pkg in &entry.debs {
        let found = fs::read_dir(&debs)?
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with(&format!("{pkg}_")) && n.ends_with(".deb"))
            })
            .count();
        ensure!(found == 1, "expected one .deb for {pkg}, found {found}");
    }
    // A cached directory is trusted as is, so it must be complete on disk
    // before it gets its name.
    for e in fs::read_dir(&debs)? {
        fs::File::open(e?.path())?.sync_all()?;
    }
    fs::File::open(&debs)?.sync_all()?;
    let root = paths.images_dir();
    fs::rename(&debs, debs_dir(paths, &entry.id))?;
    fs::File::open(&root)?.sync_all()?;
    Ok(())
}

/// Lays out a private apt root in `dir` and returns its config file, for
/// `APT_CONFIG`. Every path apt uses then resolves inside `dir`: the host's
/// `apt.conf.d`, sources, preferences, keyrings and package state are never
/// read, and only `keyring` (the resolved `deb_keyring`) is trusted for the
/// catalog's sources.
fn apt_root(dir: &Path, entry: &CatalogEntry, keyring: &Path) -> Result<PathBuf> {
    let d = dir.to_str().context("data path is not UTF-8")?;
    ensure!(
        !d.contains(['"', '\n']),
        "data path {d:?} cannot go into an apt config"
    );
    for sub in [
        "etc/apt/apt.conf.d",
        "etc/apt/preferences.d",
        "var/lib/apt/lists/partial",
        "debs",
    ] {
        ensure_private_dir(&dir.join(sub))?;
    }
    // `signed-by=` takes a comma-separated list, and the line ends at
    // whitespace or `]`: one plain keyring path only.
    let keyring = keyring.to_str().context("keyring path is not UTF-8")?;
    ensure!(
        keyring.starts_with('/')
            && keyring
                .bytes()
                .all(|c| c.is_ascii_graphic() && !b"[],#".contains(&c)),
        "keyring path {keyring:?} cannot go into an apt source"
    );
    let sources: String = entry
        .deb_sources
        .iter()
        .map(|s| format!("deb [arch=amd64 signed-by={keyring}] {s}\n"))
        .collect();
    fs::write(dir.join("etc/apt/sources.list"), sources)?;
    // Relative paths resolve under `Dir`. The status file is the only
    // absolute default that matters: no host package state. An index that
    // fails to download is an error, not a fallback to older packages.
    let conf = dir.join("apt.conf");
    fs::write(
        &conf,
        format!(
            "Dir \"{d}/\";\n\
             Dir::State::status \"/dev/null\";\n\
             APT::Architecture \"amd64\";\n\
             APT::Architectures {{ \"amd64\"; }};\n\
             Acquire::Languages \"none\";\n\
             APT::Update::Error-Mode \"any\";\n"
        ),
    )?;
    Ok(conf)
}

/// Fetches `url` over HTTPS only (redirects included), with a size cap and
/// stall detection.
async fn download(url: &str, dest: &Path, max_size: u64, resume: bool) -> Result<()> {
    let mut cmd = Command::new("curl");
    // `-q` must come first: it stops curl from reading ~/.curlrc.
    cmd.args(["-q", "--proto", "=https", "--tlsv1.2", "--fail"])
        .args(["--silent", "--show-error", "--location", "--retry", "3"])
        .args(["--connect-timeout", "30", "--speed-limit", "10240"])
        .args([
            "--speed-time",
            "60",
            "--max-filesize",
            &max_size.to_string(),
        ]);
    if resume {
        cmd.args(["--continue-at", "-"]);
    }
    cmd.arg("--output").arg(dest).arg(url);
    run_tool(&mut cmd, Duration::from_secs(3 * 3600))
        .await
        .with_context(|| format!("download of {url} failed"))?;
    Ok(())
}

/// The keyring file for a catalog `keyring`: an absolute host path as is,
/// or a vendored keyring, (re)written from the binary to
/// `<data>/images/keys/` so a changed copy on disk is never trusted.
fn keyring_path(paths: &Paths, keyring: &str) -> Result<PathBuf> {
    if keyring.starts_with('/') {
        return Ok(keyring.into());
    }
    let (name, bytes) = KEYS
        .iter()
        .find(|(name, _)| *name == keyring)
        .with_context(|| format!("no keyring {keyring:?} in catalog/keys/"))?;
    let dir = paths.images_dir().join("keys");
    ensure_private_dir(&dir)?;
    let path = dir.join(name);
    safe_remove(&dir, &path)?;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .and_then(|mut f| std::io::Write::write_all(&mut f, bytes))
        .with_context(|| format!("cannot write {}", path.display()))?;
    Ok(path)
}

/// Runs `gpgv` on the checksum list `sums` and returns the signed text and
/// the VALIDSIG fields.
/// With `sig`, that is a detached signature over all of `sums`. Without,
/// `sums` is clearsigned and the text is what gpgv writes to `out` as
/// signed, never the downloaded file: lines outside the signed part are
/// dropped.
///
/// Requires exactly one valid signature by `fingerprint` and no bad,
/// expired or revoked one. gpgv's exit code alone accepts any key in the
/// keyring, revoked ones included.
async fn signed_text(
    keyring: &Path,
    fingerprint: &str,
    sums: &Path,
    sig: Option<&Path>,
    out: &Path,
) -> Result<(String, Vec<String>)> {
    let output = Path::new("--output");
    let (args, text) = match sig {
        Some(sig) => (vec![sig, sums], sums),
        None => (vec![output, out, sums], out),
    };
    let validsig = gpgv(keyring, fingerprint, &args, 30).await?;
    Ok((fs::read_to_string(text)?, validsig))
}

/// Runs `gpgv` with `args` and checks its status (see
/// [`check_gpg_status`]); returns the VALIDSIG fields.
async fn gpgv(
    keyring: &Path,
    fingerprint: &str,
    args: &[&Path],
    timeout: u64,
) -> Result<Vec<String>> {
    let mut cmd = Command::new("gpgv");
    cmd.args(["--status-fd", "1", "--keyring"])
        .arg(keyring)
        .args(args);
    let status = run_tool(&mut cmd, Duration::from_secs(timeout)).await?;
    check_gpg_status(&String::from_utf8_lossy(&status), fingerprint)
}

/// Requires exactly one valid signature by `fingerprint` and nothing bad;
/// returns the fields of its VALIDSIG line: `<fpr> <date> <created>
/// <expires> <version> <reserved> <pubkey algo> <hash algo> <class> <primary
/// fpr>`, where `created` is in seconds or, from some GnuPG versions,
/// ISO 8601.
fn check_gpg_status(status: &str, fingerprint: &str) -> Result<Vec<String>> {
    let mut valid = vec![];
    for line in status.lines() {
        let mut words = line.split_whitespace();
        if words.next() != Some("[GNUPG:]") {
            continue;
        }
        match words.next() {
            // ERROR and FAILURE: gpgv hit something it could not process,
            // such as unsigned data next to a signed block.
            Some(
                "BADSIG" | "ERRSIG" | "EXPSIG" | "EXPKEYSIG" | "REVKEYSIG" | "ERROR" | "FAILURE",
            ) => {
                bail!("gpgv reported: {line}")
            }
            // The last field is the primary key.
            Some("VALIDSIG") => {
                let fields: Vec<String> = words.map(str::to_owned).collect();
                ensure!(
                    fields.last().map(String::as_str) == Some(fingerprint),
                    "signed by an unexpected key: {line}"
                );
                valid.push(fields);
            }
            _ => {}
        }
    }
    ensure!(
        valid.len() == 1,
        "expected one valid signature by {fingerprint}, found {}",
        valid.len()
    );
    Ok(valid.remove(0))
}

/// Finds the SHA-256 of `file` in a checksum list: `<hex> *<name>` (GNU)
/// or `SHA256 (<name>) = <hex>` (BSD) lines. Other lines are skipped.
pub fn expected_sha256(sums: &str, file: &str, format: SumsFormat) -> Result<String> {
    for line in sums.lines() {
        let found = match format {
            SumsFormat::Gnu => line
                .split_once(' ')
                .map(|(hash, name)| (hash, name.trim_start_matches([' ', '*']))),
            SumsFormat::Bsd => line
                .strip_prefix("SHA256 (")
                .and_then(|l| l.rsplit_once(") = "))
                .map(|(name, hash)| (hash, name)),
        };
        let Some((hash, name)) = found else {
            continue;
        };
        if name == file {
            ensure!(
                hash.len() == 64 && hash.bytes().all(|c| c.is_ascii_hexdigit()),
                "malformed checksum line for {file}"
            );
            return Ok(hash.to_ascii_lowercase());
        }
    }
    bail!("{file} is not in the checksum list")
}

/// Streams a file through hash `D` on a blocking thread; returns it in
/// lower-case hex.
pub async fn hash_file<D: Digest + 'static>(path: &Path) -> Result<String> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || {
        let mut f = fs::File::open(&path)?;
        let mut hasher = D::new();
        let mut buf = vec![0; 1 << 20];
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect())
    })
    .await?
}

/// Facts about a verified image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageInfo {
    pub virtual_size: u64,
}

/// Runs `qemu-img info` (format pinned to qcow2, so nothing is probed, and
/// backing files are not opened) and refuses anything but a self-contained
/// qcow2. A crafted image could otherwise point its backing file or data
/// file at a host file.
///
/// Today it only parses images whose hash was verified first. Before it is
/// used on untrusted user imports, run it under `prlimit --as=1G --cpu=30`
/// as QEMU's documentation recommends.
pub async fn check_image(path: &Path) -> Result<ImageInfo> {
    let out = run_tool(
        Command::new("qemu-img")
            .args(["info", "-f", "qcow2", "--output=json"])
            .arg(path),
        Duration::from_secs(30),
    )
    .await
    .with_context(|| format!("{} is not a valid qcow2 image", path.display()))?;
    check_image_info(&serde_json::from_slice(&out)?)
}

fn check_image_info(info: &Value) -> Result<ImageInfo> {
    ensure!(info["format"] == "qcow2", "image is not qcow2");
    ensure!(
        info.get("backing-filename").is_none() && info.get("full-backing-filename").is_none(),
        "image has a backing file"
    );
    ensure!(
        info["format-specific"]["data"].get("data-file").is_none(),
        "image has an external data file"
    );
    let virtual_size = info["virtual-size"]
        .as_u64()
        .context("image has no virtual size")?;
    Ok(ImageInfo { virtual_size })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_parses() {
        let e = find("ubuntu-26.04").unwrap();
        assert_eq!(e.file(), "resolute-server-cloudimg-amd64.img");
        assert_eq!(e.trust, Trust::SignedSums);
        assert!(e.debs.contains(&"qemu-guest-agent".to_owned()));
        let e = find("ubuntu-24.04").unwrap();
        assert_eq!(e.file(), "noble-server-cloudimg-amd64.img");
        assert_eq!(e.debs, ["qemu-guest-agent", "liburing2"]);
        let e = find("fedora-44").unwrap();
        assert_eq!(e.file(), "Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2");
        assert_eq!(e.sig_url.as_deref(), Some(""));
        assert_eq!(e.sums_format, Some(SumsFormat::Bsd));
        assert_eq!(e.agent, Agent::Preinstalled);
        let e = find("arch").unwrap();
        assert_eq!(e.file(), "Arch-Linux-x86_64-cloudimg.qcow2");
        assert_eq!(
            (e.trust, e.firmware, e.agent),
            (Trust::SignedImage, Firmware::Uefi, Agent::Preinstalled)
        );
        assert_eq!(e.sig_url.unwrap(), format!("{}.sig", e.url));
        let e = find("debian-13").unwrap();
        assert_eq!(e.file(), "debian-13-generic-amd64-20261015-2632.qcow2");
        assert_eq!(
            (e.trust, e.firmware, e.agent),
            (Trust::Pinned, Firmware::SecureBoot, Agent::Deb)
        );
        assert_eq!(e.debs, ["qemu-guest-agent"]);
        assert_eq!(e.deb_keyring.as_deref(), Some("debian-archive-trixie.gpg"));
        let e = find("ubuntu-26.04-desktop").unwrap();
        assert_eq!(e.file(), "ubuntu-26.04.1-desktop-amd64.iso");
        assert_eq!(
            (e.kind, e.trust, e.sums_format, e.agent, e.moving),
            (
                Kind::Iso,
                Trust::SignedSums,
                Some(SumsFormat::Gnu),
                Agent::Manual,
                false
            )
        );
        let e = find("fedora-44-workstation").unwrap();
        assert_eq!(e.file(), "Fedora-Workstation-Live-44-1.7.x86_64.iso");
        assert_eq!(
            (e.kind, e.sums_format, e.agent, e.sig_url.as_deref()),
            (Kind::Iso, Some(SumsFormat::Bsd), Agent::Manual, Some(""))
        );
        for e in catalog() {
            assert_eq!(
                e.kind == Kind::Iso,
                e.id.ends_with("-desktop") || e.id.ends_with("-workstation")
            );
        }
        assert!(find("../x").is_err());
    }

    /// The built-in entry with `edit` applied: a TOML value sets a key,
    /// `None` removes it.
    fn entry_with(edit: &[(&str, Option<&str>)]) -> Result<CatalogEntry> {
        edited(CATALOG[0], edit)
    }

    fn edited(text: &str, edit: &[(&str, Option<&str>)]) -> Result<CatalogEntry> {
        let mut t: toml::Table = toml::from_str(text)?;
        for &(key, value) in edit {
            match value {
                Some(v) => t.insert(
                    key.into(),
                    toml::from_str::<toml::Table>(&format!("v = {v}"))?["v"].clone(),
                ),
                None => t.remove(key),
            };
        }
        let entry: CatalogEntry = t.try_into()?;
        entry.validate()?;
        Ok(entry)
    }

    #[test]
    fn catalog_invariants() {
        entry_with(&[]).unwrap();
        let err = |edit: &[(&str, Option<&str>)]| format!("{:#}", entry_with(edit).unwrap_err());
        let sha = format!("{:?}", "a".repeat(128));
        let pinned = [
            ("trust", Some(r#""pinned""#)),
            ("sha512", Some(sha.as_str())),
            ("sums_url", None),
            ("sig_url", None),
            ("sums_format", None),
            ("keyring", None),
            ("signing_key", None),
            ("moving", None),
        ];
        entry_with(&pinned).unwrap();
        // pinned: sha512 required, keys refused.
        assert!(err(&pinned[..1]).contains("pinned needs"));
        let mut keyed = pinned.to_vec();
        keyed[6] = (
            "signing_key",
            Some(r#""D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81""#),
        );
        assert!(err(&keyed).contains("pinned needs"));
        let mut short = pinned.to_vec();
        short[1] = ("sha512", Some(r#""abc""#));
        assert!(err(&short).contains("pinned needs"));
        // signed-sums: every part present.
        assert!(err(&[("sig_url", None)]).contains("signed-sums needs"));
        assert!(err(&[("sha512", Some(r#""a""#))]).contains("signed-sums needs"));
        // deb: packages required, and no options among them.
        assert!(err(&[("debs", Some("[]"))]).contains("needs debs"));
        for k in ["deb_sources", "deb_keyring"] {
            assert!(err(&[(k, None)]).contains("needs debs"), "{k}");
        }
        for bad in [
            "http://archive.ubuntu.com/ubuntu resolute main",
            "https://archive.ubuntu.com/ubuntu resolute",
            "[trusted=yes] https://archive.ubuntu.com/ubuntu resolute main",
            "https://archive.ubuntu.com/ubuntu resolute main\ndeb https://x y z",
            "https://archive.ubuntu.com/ubuntu  resolute main",
        ] {
            let v = format!("[{bad:?}]");
            assert!(
                err(&[("deb_sources", Some(&v))]).contains("deb source"),
                "{bad}"
            );
        }
        for bad in [
            "ubuntu-archive-keyring.gpg",
            "/k.gpg] https://x y z",
            "/usr/share/keyrings/ubuntu-archive-keyring.gpg,/tmp/evil.gpg",
            "/usr/share/keyrings/ubuntu-archive-keyring.gpg,0123456789ABCDEF0123456789ABCDEF01234567.gpg",
            "/usr/share/keyrings",
        ] {
            let v = format!("{bad:?}");
            assert!(
                err(&[("deb_keyring", Some(&v))]).contains("absolute"),
                "{bad}"
            );
        }
        // A vendored keyring by name.
        entry_with(&[("deb_keyring", Some(r#""debian-archive-trixie.gpg""#))]).unwrap();
        assert!(err(&[("debs", Some(r#"["-o"]"#))]).contains("package name"));
        assert!(err(&[("agent", Some(r#""preinstalled""#))]).contains("no debs"));
        let bare = [
            ("agent", Some(r#""preinstalled""#)),
            ("debs", None),
            ("deb_sources", None),
            ("deb_keyring", None),
        ];
        entry_with(&bare).unwrap();
        assert!(err(&bare[..3]).contains("no debs"));
        // Clearsigned BSD checksums with a vendored keyring.
        entry_with(&[
            ("sig_url", Some(r#""""#)),
            ("sums_format", Some(r#""bsd""#)),
            ("keyring", Some(r#""fedora.gpg""#)),
        ])
        .unwrap();
        for bad in ["nope.gpg", "keys/fedora.gpg", "", "/a b.gpg"] {
            let v = format!("{bad:?}");
            assert!(err(&[("keyring", Some(&v))]).contains("keyring"), "{bad}");
        }
        // HTTPS only; an empty URL only as the clearsigned sig_url.
        assert!(err(&[("url", Some(r#""http://example.com/a.img""#))]).contains("https"));
        assert!(err(&[("sums_url", Some(r#""ftp://example.com/S""#))]).contains("https"));
        assert!(err(&[("sums_url", Some(r#""""#))]).contains("https"));
        let both_empty = [("sig_url", Some(r#""""#)), ("sums_url", Some(r#""""#))];
        assert!(err(&both_empty).contains("https"));
        let signed_image = [
            ("trust", Some(r#""signed-image""#)),
            ("sig_url", Some(r#""""#)),
            ("sums_url", None),
            ("sums_format", None),
            ("moving", None),
        ];
        assert!(err(&signed_image).contains("https"));
        let mut signed_image = signed_image.to_vec();
        signed_image[1] = ("sig_url", Some(r#""https://example.com/a.img.sig""#));
        entry_with(&signed_image).unwrap();
        signed_image[4] = ("moving", Some("true"));
        assert!(err(&signed_image).contains("moving applies"));
        signed_image[4] = ("moving", None);
        signed_image[2] = ("sums_url", Some(r#""https://example.com/S""#));
        assert!(err(&signed_image).contains("signed-image needs"));
        // Full fingerprints only.
        for bad in ["7DB87C81", "d2eb44626fddc30b513d5bb71a5d6c4c7db87c81"] {
            let v = format!("{bad:?}");
            assert!(err(&[("signing_key", Some(&v))]).contains("40 upper-case"));
        }
        // Unknown fields and values are refused.
        assert!(entry_with(&[("release", Some(r#""26.04""#))]).is_err());
        assert!(entry_with(&[("os", Some(r#""macos""#))]).is_err());
        assert!(err(&[("os", Some(r#""windows""#))]).contains("not supported yet"));
        entry_with(&[("firmware", Some(r#""uefi""#))]).unwrap();
        // `moving` is for signed-sums: signed-image always checks the age,
        // and a pinned file cannot move.
        entry_with(&[("moving", Some("true"))]).unwrap();
        assert!(err(&[pinned.as_slice(), &[("moving", Some("true"))]].concat()).contains("moving"));
    }

    /// ISO entries: signed-sums, a .iso URL, a manual agent and no seed
    /// options; cloud images never have a manual agent.
    #[test]
    fn iso_invariants() {
        let iso = include_str!("../catalog/ubuntu-26.04-desktop.toml");
        let err = |edit: &[(&str, Option<&str>)]| format!("{:#}", edited(iso, edit).unwrap_err());
        edited(iso, &[]).unwrap();
        assert!(err(&[("agent", Some(r#""preinstalled""#))]).contains("only an ISO"));
        assert!(err(&[("kind", None)]).contains("only an ISO"));
        assert!(err(&[("kind", Some(r#""cloud-image""#))]).contains("only an ISO"));
        assert!(entry_with(&[("kind", Some(r#""disk""#))]).is_err());
        // A cloud image (Deb, the default kind) with a manual agent.
        let manual = [
            ("agent", Some(r#""manual""#)),
            ("debs", None),
            ("deb_sources", None),
            ("deb_keyring", None),
        ];
        assert!(format!("{:#}", entry_with(&manual).unwrap_err()).contains("only an ISO"));
        assert!(
            err(&[("debs", Some(r#"["qemu-guest-agent"]"#))])
                .contains("manual agent takes no debs")
        );
        assert!(err(&[("url", Some(r#""https://example.com/a.img""#))]).contains("an ISO needs"));
        assert!(err(&[("internet", Some("true"))]).contains("an ISO needs"));
        assert!(err(&[("qga_permissive", Some("true"))]).contains("an ISO needs"));
        let sha = format!("{:?}", "a".repeat(128));
        let pinned = [
            ("trust", Some(r#""pinned""#)),
            ("sha512", Some(sha.as_str())),
            ("sums_url", None),
            ("sig_url", None),
            ("sums_format", None),
            ("keyring", None),
            ("signing_key", None),
        ];
        assert!(err(&pinned).contains("an ISO needs"));
    }

    /// Only images verified with the internet profile take it.
    #[test]
    fn internet_profile_per_image() {
        for (id, ok) in [
            ("ubuntu-26.04", true),
            ("ubuntu-24.04", true),
            ("fedora-44", false),
            ("arch", false),
            ("debian-13", false),
            ("ubuntu-26.04-desktop", false),
            ("fedora-44-workstation", false),
        ] {
            let e = find(id).unwrap();
            e.check_net(NetProfile::Offline).unwrap();
            let r = e.check_net(NetProfile::Internet);
            assert_eq!(r.is_ok(), ok, "{id}");
            if let Err(err) = r {
                assert_eq!(
                    err.to_string(),
                    format!("{id}: the internet profile is not supported for this image yet")
                );
            }
        }
    }

    /// Each vendored keyring holds exactly the primary keys that catalog
    /// entries pin for it, and every vendored keyring is used. Needs `gpg`.
    #[test]
    fn vendored_keys_are_pinned() {
        let catalog = catalog();
        for (name, bytes) in KEYS {
            let dir = tempfile::tempdir().unwrap();
            let file = dir.path().join(name);
            fs::write(&file, bytes).unwrap();
            let out = std::process::Command::new("gpg")
                .arg("--homedir")
                .arg(dir.path())
                .args(["--batch", "--show-keys", "--with-colons"])
                .arg(&file)
                .output()
                .unwrap();
            assert!(out.status.success(), "{name}");
            let listing = String::from_utf8(out.stdout).unwrap();
            // The first fpr record after each pub record (designated
            // revokers, `rvk`, may come in between).
            let listing = format!("\n{listing}");
            let mut found: Vec<&str> = listing
                .split("\npub:")
                .skip(1)
                .filter_map(|key| key.lines().find_map(|l| l.strip_prefix("fpr:::::::::")))
                .map(|f| f.trim_end_matches(':'))
                .collect();
            let mut pinned: Vec<&str> = catalog
                .iter()
                .filter(|e| e.keyring.as_deref() == Some(*name))
                .filter_map(|e| e.signing_key.as_deref())
                .collect();
            // apt checks the archive keys itself; their fingerprints are
            // pinned here.
            if catalog
                .iter()
                .any(|e| e.deb_keyring.as_deref() == Some(*name))
            {
                assert_eq!(*name, "debian-archive-trixie.gpg");
                pinned.extend([
                    // Debian Archive Automatic Signing Key (13/trixie)
                    "04B54C3CDCA79751B16BC6B5225629DF75B188BD",
                    // Debian Security Archive Automatic Signing Key (13/trixie)
                    "5E04A1E3223A19A20706E20F9904613D4CCE68C6",
                ]);
            }
            found.sort();
            pinned.sort();
            pinned.dedup();
            assert!(!pinned.is_empty(), "{name} is not used");
            assert_eq!(found, pinned, "{name}");
            // gpg's view is not apt's (sqv): the bytes are pinned too, so
            // a packet gpg skips cannot slip in unseen.
            let sha256: String = Sha256::digest(bytes)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            let want = match *name {
                "fedora.gpg" => "ee42b9c07cf45061e59446506442fed9a68270e2a65b775d41b2549501fc4dbc",
                "arch-boxes.gpg" => {
                    "f21550af3ff9c63fee0f109127c1e61a54f0e382285eb3c557576770b7fb79c1"
                }
                "debian-archive-trixie.gpg" => {
                    "9429548ea361e7182aa8427ac1d0a4bea09af5d71edce5761ffbe8789b943537"
                }
                _ => panic!("{name}: pin its SHA-256 here"),
            };
            assert_eq!(sha256, want, "{name}");
        }
        assert_eq!(
            find("fedora-44").unwrap().signing_key.as_deref(),
            Some("36F612DCF27F7D1A48A835E4DBFCF71C6D9F90A6")
        );
        assert_eq!(
            find("arch").unwrap().signing_key.as_deref(),
            Some("1B9A16984A4E8CB448712D2AE0B78BF4326C6F8F")
        );
    }

    /// Vendored keyrings are written fresh to `<data>/images/keys/` (0700).
    #[test]
    fn vendored_keyring_is_written() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path().join("data"), dir.path().join("run")).unwrap();
        let host = "/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg";
        assert_eq!(keyring_path(&paths, host).unwrap(), Path::new(host));
        let keys = paths.images_dir().join("keys");
        assert!(!keys.exists());
        let path = keyring_path(&paths, "fedora.gpg").unwrap();
        assert_eq!(path, keys.join("fedora.gpg"));
        let mode = fs::metadata(&keys).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        fs::write(&path, b"changed").unwrap();
        keyring_path(&paths, "fedora.gpg").unwrap();
        assert_eq!(fs::read(&path).unwrap(), KEYS[0].1);
        assert!(keyring_path(&paths, "nope.gpg").is_err());
    }

    #[test]
    fn sha256sums_lookup() {
        let h = "8800651811af9a85465ad1d552add729947bb16488dddb4a9b5305a3d97332b2";
        let sums = format!(
            "{} *resolute-server-cloudimg-amd64.manifest\n{h} *resolute-server-cloudimg-amd64.img\n",
            "1".repeat(64)
        );
        let gnu = |sums: &str, file: &str| expected_sha256(sums, file, SumsFormat::Gnu);
        assert_eq!(gnu(&sums, "resolute-server-cloudimg-amd64.img").unwrap(), h);
        assert!(gnu(&sums, "resolute-server-cloudimg-amd64").is_err());
        assert!(gnu("zz *a.img\n", "a.img").is_err());
        assert_eq!(gnu(&format!("{h}  a.img\n"), "a.img").unwrap(), h);
        // BSD lines are not GNU lines.
        assert!(gnu(&format!("SHA256 (a.img) = {h}\n"), "a.img").is_err());
    }

    #[test]
    fn bsd_sums_lookup() {
        let h = "28680fe5b371a5a82ebf43a31926e086a168e59949d03969c5093e7071f90b7f";
        let file = "Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2";
        let sums = format!(
            "# {file}: 583729152 bytes\n\
             SHA256 (Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2.xz) = {}\n\
             SHA256 ({file}) = {h}\n",
            "1".repeat(64)
        );
        let bsd = |sums: &str, file: &str| expected_sha256(sums, file, SumsFormat::Bsd);
        assert_eq!(bsd(&sums, file).unwrap(), h);
        assert_eq!(bsd(&sums.to_uppercase(), &file.to_uppercase()).unwrap(), h);
        assert!(bsd(&sums, "Fedora-Cloud-Base-Generic-44-1.7.x86_64").is_err());
        assert!(bsd(&format!("SHA256 (a.img) = {}\n", &h[1..]), "a.img").is_err());
        assert!(bsd(&format!("SHA512 (a.img) = {h}\n"), "a.img").is_err());
        assert!(bsd(&format!("{h} *a.img\n"), "a.img").is_err());
        // A name with ") = " in it: the hash is after the last one.
        assert_eq!(
            bsd(&format!("SHA256 (a) = b) = {h}\n"), "a) = b").unwrap(),
            h
        );
    }

    #[tokio::test]
    async fn hashes_of_file() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("f");
        fs::write(&f, b"abc").unwrap();
        assert_eq!(
            hash_file::<Sha256>(&f).await.unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let sha512 = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
        assert_eq!(hash_file::<Sha512>(&f).await.unwrap(), sha512);
        // pinned: a match keeps the file, a mismatch deletes it.
        check_hash::<Sha512>(dir.path(), &f, sha512).await.unwrap();
        assert!(f.exists());
        let err = check_hash::<Sha512>(dir.path(), &f, &"0".repeat(128))
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("hash mismatch"), "{err:#}");
        assert!(!f.exists());
    }

    /// A planted partial download larger than the cap, or a directory, is
    /// removed before it could be resumed or hashed; a symlink fails.
    #[test]
    fn oversized_partial_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let root = &fs::canonicalize(dir.path()).unwrap();
        let f = root.join("x.part");
        assert!(!drop_oversized(root, &f, 4).unwrap());
        fs::write(&f, b"1234").unwrap();
        assert!(!drop_oversized(root, &f, 4).unwrap());
        assert!(f.exists());
        fs::write(&f, b"12345").unwrap();
        assert!(drop_oversized(root, &f, 4).unwrap());
        assert!(!f.exists());
        ensure_private_dir(&f).unwrap();
        assert!(drop_oversized(root, &f, 4).unwrap());
        assert!(!f.exists());
        // A symlink is refused outright (safe_remove): the pull fails.
        std::os::unix::fs::symlink("/etc/hostname", &f).unwrap();
        assert!(drop_oversized(root, &f, 1 << 20).is_err());
    }

    #[test]
    fn gpg_status_is_pinned_to_one_key() {
        let fpr = "D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81";
        let good = format!(
            "[GNUPG:] NEWSIG\n[GNUPG:] GOODSIG 1A5D6C4C7DB87C81 UEC\n\
             [GNUPG:] VALIDSIG {fpr} 2026-09-29 1790640937 0 4 0 1 10 00 {fpr}\n"
        );
        let fields = check_gpg_status(&good, fpr).unwrap();
        assert_eq!(fields.len(), 10);
        assert_eq!(
            (&*fields[2], fields.last().unwrap().as_str()),
            ("1790640937", fpr)
        );
        let other = good.replace(
            &format!("00 {fpr}"),
            "00 4A3CE3CD565D7EB5C810E2B97FF3F408476CF100",
        );
        assert!(check_gpg_status(&other, fpr).is_err());
        assert!(check_gpg_status(&format!("{good}{good}"), fpr).is_err());
        assert!(check_gpg_status("[GNUPG:] NEWSIG\n", fpr).is_err());
        for bad in ["REVKEYSIG", "EXPKEYSIG", "BADSIG", "ERRSIG"] {
            let status = format!("{good}[GNUPG:] {bad} 1A5D6C4C7DB87C81 UEC\n");
            assert!(check_gpg_status(&status, fpr).is_err(), "{bad}");
        }
        for bad in [
            "ERROR proc_pkt.plaintext 89_BAD_DATA",
            "FAILURE gpg-exit 33554433",
        ] {
            let status = format!("{good}[GNUPG:] {bad}\n");
            assert!(check_gpg_status(&status, fpr).is_err(), "{bad}");
        }
    }

    /// signed-image: kind and age of the signature, from the VALIDSIG line
    /// gpgv gave for a real Arch image.
    #[test]
    fn image_signature_checks() {
        let arch = "656E4C5AC1CC3B86E539D97E343635A6859A9174 2026-10-15 1792066023 0 4 0 22 10 00 1B9A16984A4E8CB448712D2AE0B78BF4326C6F8F";
        let status = format!(
            "[GNUPG:] VALIDSIG {arch}
"
        );
        let fields = check_gpg_status(&status, "1B9A16984A4E8CB448712D2AE0B78BF4326C6F8F").unwrap();
        let check = |edit: &[(usize, &str)], now: u64| {
            let mut f = fields.clone();
            for &(i, v) in edit {
                f[i] = v.into();
            }
            check_image_sig(&f, now)
        };
        let (day, created) = (86_400, 1_792_066_023);
        check(&[], created).unwrap();
        check(&[], created + 45 * day).unwrap();
        let stale = format!("{:#}", check(&[], created + 46 * day).unwrap_err());
        assert!(
            stale.contains("46 days old (at most 45): the mirror looks stale, or upstream has not rebuilt in 46 days"),
            "{stale}"
        );
        // Up to a day of clock skew; later is refused.
        check(&[], created - day).unwrap();
        assert!(format!("{:#}", check(&[], created - day - 1).unwrap_err()).contains("future"));
        // SHA-256 is fine; SHA-1 is not, nor a text or other class.
        check(&[(7, "8")], created).unwrap();
        for edit in [(7, "2"), (8, "01"), (8, "1f")] {
            assert!(check(&[edit], created).is_err(), "{edit:?}");
        }
        // A time that is not in seconds (ISO 8601) is refused.
        assert!(check(&[(2, "20261015T121313")], created).is_err());
        assert!(check_image_sig(&fields[..5], created).is_err());
    }

    /// Real gpgv against a throwaway key, detached and clearsigned: a good
    /// signature passes; a wrong pinned key and a tampered signed text fail;
    /// text outside a clearsigned block is ignored. Needs `gpg` and `gpgv`.
    #[tokio::test]
    async fn gpgv_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("gnupg");
        ensure_private_dir(&home).unwrap();
        let gpg = |args: &[&str]| {
            let out = std::process::Command::new("gpg")
                .arg("--homedir")
                .arg(&home)
                .args(["--batch", "--quiet", "--pinentry-mode", "loopback"])
                .args(["--passphrase", ""])
                .args(args)
                .output()
                .unwrap();
            let err = String::from_utf8_lossy(&out.stderr);
            assert!(out.status.success(), "{err}");
            out.stdout
        };
        gpg(&[
            "--quick-gen-key",
            "test@stallo.invalid",
            "ed25519",
            "sign",
            "never",
        ]);
        let listing = String::from_utf8(gpg(&["--with-colons", "--list-keys"])).unwrap();
        let fpr = listing
            .lines()
            .find_map(|l| l.strip_prefix("fpr:::::::::"))
            .unwrap()
            .trim_end_matches(':')
            .to_owned();
        let keyring = dir.path().join("keyring.gpg");
        fs::write(&keyring, gpg(&["--export"])).unwrap();
        let data = dir.path().join("SHA256SUMS");
        let sig = dir.path().join("SHA256SUMS.gpg");
        let out = dir.path().join("SHA256SUMS.signed");
        fs::write(&data, b"abc *a.img\n").unwrap();
        let (sig_s, data_s) = (sig.to_str().unwrap(), data.to_str().unwrap());
        gpg(&["--detach-sign", "--output", sig_s, data_s]);

        // Detached.
        let check = |key: String, sig: Option<PathBuf>| {
            let (keyring, data, out) = (keyring.clone(), data.clone(), out.clone());
            async move {
                let _ = fs::remove_file(&out);
                signed_text(&keyring, &key, &data, sig.as_deref(), &out)
                    .await
                    .map(|(text, _)| text)
            }
        };
        let text = check(fpr.clone(), Some(sig.clone())).await.unwrap();
        assert_eq!(text, "abc *a.img\n");
        assert!(check("0".repeat(40), Some(sig.clone())).await.is_err());
        fs::write(&data, b"abd *a.img\n").unwrap();
        assert!(check(fpr.clone(), Some(sig.clone())).await.is_err());
        // A detached signature is not a clearsigned file.
        assert!(check(fpr.clone(), None).await.is_err());
        // Over an image (signed-image): gives the signature time.
        let image = dir.path().join("a.img");
        fs::write(
            &image,
            (0..=255u8).cycle().take(1 << 20).collect::<Vec<u8>>(),
        )
        .unwrap();
        let image_sig = dir.path().join("a.img.sig");
        let image_s = image.to_str().unwrap();
        gpg(&[
            "--detach-sign",
            "--output",
            image_sig.to_str().unwrap(),
            image_s,
        ]);
        let validsig = gpgv(&keyring, &fpr, &[&image_sig, &image], 30)
            .await
            .unwrap();
        check_image_sig(&validsig, now_secs().unwrap()).unwrap();
        // The signature over the checksum list is not one over the image.
        assert!(gpgv(&keyring, &fpr, &[&sig, &image], 30).await.is_err());
        // Nor is a signed message of other content, compressed or not.
        let other = dir.path().join("other");
        fs::write(&other, b"other\n").unwrap();
        for z in ["6", "0"] {
            let msg = dir.path().join(format!("msg{z}.gpg"));
            gpg(&[
                "--yes",
                "-z",
                z,
                "--sign",
                "--output",
                msg.to_str().unwrap(),
                other.to_str().unwrap(),
            ]);
            assert!(
                gpgv(&keyring, &fpr, &[&msg, &image], 30).await.is_err(),
                "-z {z}"
            );
        }
        // A text-mode signature verifies but is not a binary one.
        let text_sig = dir.path().join("a.img.txt.sig");
        gpg(&[
            "--textmode",
            "--detach-sign",
            "--output",
            text_sig.to_str().unwrap(),
            image_s,
        ]);
        let validsig = gpgv(&keyring, &fpr, &[&text_sig, &image], 30)
            .await
            .unwrap();
        assert!(check_image_sig(&validsig, now_secs().unwrap()).is_err());
        let mut tampered = fs::read(&image).unwrap();
        tampered[1000] ^= 1;
        fs::write(&image, tampered).unwrap();
        assert!(
            gpgv(&keyring, &fpr, &[&image_sig, &image], 30)
                .await
                .is_err()
        );

        // Clearsigned: only the signed part counts.
        let (good, evil) = ("a".repeat(64), "e".repeat(64));
        let plain = dir.path().join("plain");
        fs::write(
            &plain,
            format!("# a.img: 3 bytes\nSHA256 (a.img) = {good}\n"),
        )
        .unwrap();
        let plain_s = plain.to_str().unwrap();
        gpg(&["--yes", "--clearsign", "--output", data_s, plain_s]);
        let clear = fs::read_to_string(&data).unwrap();
        let lookup = |text: &str| expected_sha256(text, "a.img", SumsFormat::Bsd);
        let text = check(fpr.clone(), None).await.unwrap();
        assert_eq!(lookup(&text).unwrap(), good);
        assert!(!text.contains("PGP"), "{text}");
        assert!(check("0".repeat(40), None).await.is_err());
        // Lines added outside the signed block are dropped.
        let line = format!("SHA256 (a.img) = {evil}\n");
        fs::write(&data, format!("{line}{clear}{line}")).unwrap();
        let text = check(fpr.clone(), None).await.unwrap();
        assert_eq!(lookup(&text).unwrap(), good);
        assert!(!text.contains(&evil));
        // A changed line inside it fails the signature.
        fs::write(&data, clear.replace(&good, &evil)).unwrap();
        assert!(check(fpr.clone(), None).await.is_err());
        // So does a line added inside it.
        let added = clear.replace("# a.img", &format!("{line}# a.img"));
        assert_ne!(added, clear);
        fs::write(&data, added).unwrap();
        assert!(check(fpr.clone(), None).await.is_err());
        // Unsigned data (a literal packet) before or after the signed block:
        // gpgv writes it to `out` but fails, so it is never parsed.
        let literal = dir.path().join("literal.asc");
        let evil_plain = dir.path().join("evil");
        fs::write(&evil_plain, &line).unwrap();
        let (lit_s, evil_s) = (literal.to_str().unwrap(), evil_plain.to_str().unwrap());
        gpg(&["--yes", "--store", "--armor", "--output", lit_s, evil_s]);
        let literal = fs::read_to_string(&literal).unwrap();
        assert!(literal.starts_with("-----BEGIN PGP MESSAGE-----"));
        for combined in [format!("{literal}{clear}"), format!("{clear}{literal}")] {
            fs::write(&data, combined).unwrap();
            assert!(check(fpr.clone(), None).await.is_err());
        }
        // Two signed blocks are two signatures: refused.
        fs::write(&data, format!("{clear}{clear}")).unwrap();
        assert!(check(fpr.clone(), None).await.is_err());
        // An unsigned list is refused.
        fs::write(&data, &line).unwrap();
        assert!(check(fpr.clone(), None).await.is_err());
    }

    /// The real Fedora 44 checksum list (tests/fixtures/) verifies with the
    /// vendored keyring and gives the image's SHA-256. Offline.
    #[tokio::test]
    async fn fedora_checksum_fixture() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path().join("data"), dir.path().join("run")).unwrap();
        let entry = find("fedora-44").unwrap();
        let keyring = keyring_path(&paths, entry.keyring.as_deref().unwrap()).unwrap();
        let sums = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/Fedora-Cloud-44-1.7-x86_64-CHECKSUM");
        assert!(
            entry
                .sums_url
                .as_deref()
                .unwrap()
                .ends_with("/Fedora-Cloud-44-1.7-x86_64-CHECKSUM")
        );
        let out = dir.path().join("signed");
        let fpr = entry.signing_key.as_deref().unwrap();
        let (text, validsig) = signed_text(&keyring, fpr, &sums, None, &out).await.unwrap();
        // Release-pinned: not `moving`, so its age is not checked.
        assert!(!entry.moving);
        assert!(sig_date(&validsig).is_some());
        assert_eq!(
            expected_sha256(&text, entry.file(), SumsFormat::Bsd).unwrap(),
            "28680fe5b371a5a82ebf43a31926e086a168e59949d03969c5093e7071f90b7f"
        );
        // Another key is refused.
        fs::remove_file(&out).unwrap();
        assert!(
            signed_text(&keyring, &"0".repeat(40), &sums, None, &out)
                .await
                .is_err()
        );
    }

    /// The real Fedora 44 Workstation checksum list (tests/fixtures/)
    /// verifies with the vendored keyring and gives the ISO's SHA-256.
    /// Offline.
    #[tokio::test]
    async fn fedora_iso_checksum_fixture() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path().join("data"), dir.path().join("run")).unwrap();
        let entry = find("fedora-44-workstation").unwrap();
        let keyring = keyring_path(&paths, entry.keyring.as_deref().unwrap()).unwrap();
        let name = "Fedora-Workstation-44-1.7-x86_64-CHECKSUM";
        assert!(
            entry
                .sums_url
                .as_deref()
                .unwrap()
                .ends_with(&format!("/{name}"))
        );
        let sums = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name);
        let out = dir.path().join("signed");
        let fpr = entry.signing_key.as_deref().unwrap();
        let (text, _) = signed_text(&keyring, fpr, &sums, None, &out).await.unwrap();
        assert_eq!(
            expected_sha256(&text, entry.file(), SumsFormat::Bsd).unwrap(),
            "1620295f6a00c27c3208f0c00b8ece4eab1ec69b9002152d97488bf26a426ddf"
        );
    }

    /// Fetches the checksum lists of the ISO entries (a few KB each, not
    /// the ISOs): `cargo test -- --ignored iso_sums_live`. Their signatures
    /// verify with the pinned keys and list the pinned files.
    #[tokio::test]
    #[ignore = "downloads checksum lists"]
    async fn iso_sums_live() {
        let dir = tempfile::tempdir().unwrap();
        for e in catalog().into_iter().filter(|e| e.kind == Kind::Iso) {
            let (text, validsig) = live_sums(&e, dir.path()).await;
            let sha = expected_sha256(&text, e.file(), e.sums_format.unwrap()).unwrap();
            eprintln!("{}: signed {}, {sha}", e.id, sig_date(&validsig).unwrap());
        }
    }

    /// Downloads and checks `e`'s checksum list into `dir`; returns the
    /// signed text and the VALIDSIG fields.
    async fn live_sums(e: &CatalogEntry, dir: &Path) -> (String, Vec<String>) {
        let paths = Paths::new(dir.join("data"), dir.join("run")).unwrap();
        let (sums, sig, out) = (
            dir.join(format!("{}.sums", e.id)),
            dir.join(format!("{}.sig", e.id)),
            dir.join(format!("{}.out", e.id)),
        );
        download(e.sums_url.as_deref().unwrap(), &sums, 1 << 20, false)
            .await
            .unwrap();
        let sig = match e.sig_url.as_deref().unwrap() {
            "" => None,
            url => {
                download(url, &sig, 1 << 20, false).await.unwrap();
                Some(sig.as_path())
            }
        };
        let keyring = keyring_path(&paths, e.keyring.as_deref().unwrap()).unwrap();
        signed_text(
            &keyring,
            e.signing_key.as_deref().unwrap(),
            &sums,
            sig,
            &out,
        )
        .await
        .unwrap()
    }

    /// Pulls the Arch image for real (network, about 600 MB):
    /// `cargo test -- --ignored signed_image_live`. A file larger than the
    /// image already sits where the download goes, as after an upstream
    /// rebuild: curl takes it as complete, the signature check fails, and
    /// the one retry downloads the image from scratch.
    #[tokio::test]
    #[ignore = "downloads the Arch image"]
    async fn signed_image_live() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path().join("data"), dir.path().join("run")).unwrap();
        ensure_private_dir(&paths.images_dir()).unwrap();
        let entry = find("arch").unwrap();
        let work = paths.images_dir().join(".partial-arch");
        ensure_private_dir(&work).unwrap();
        let stale = fs::File::create(work.join(format!("{}.part", url_key(&entry.url)))).unwrap();
        stale.set_len(entry.max_size).unwrap();
        pull(&paths, &entry).await.unwrap();
        let image = image_path(&paths, "arch");
        let mode = fs::metadata(&image).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o444);
        assert!(check_image(&image).await.unwrap().virtual_size > 0);
        assert_eq!(
            fs::read_dir(paths.images_dir()).unwrap().count(),
            3,
            "only the image, its record and the keys are left"
        );
        let record = pulled(&paths, "arch").unwrap();
        assert_eq!(record.sha256, hash_file::<Sha256>(&image).await.unwrap());
        assert!(record.sig_date.is_some());
    }

    /// The private apt root, checked offline with apt itself: every path
    /// resolves inside it, and apt sees the catalog's sources with the
    /// pinned keyring and nothing of the host's (which may have PPAs).
    #[test]
    fn apt_root_is_private() {
        let dir = tempfile::tempdir().unwrap();
        let entry = find("ubuntu-26.04").unwrap();
        let keyring = Path::new(entry.deb_keyring.as_deref().unwrap());
        let conf = apt_root(dir.path(), &entry, keyring).unwrap();
        let run = |args: &[&str]| {
            let out = std::process::Command::new(args[0])
                .args(&args[1..])
                .env("APT_CONFIG", &conf)
                .current_dir(dir.path().join("debs"))
                .output()
                .unwrap();
            let (stdout, stderr) = (
                String::from_utf8(out.stdout).unwrap(),
                String::from_utf8_lossy(&out.stderr),
            );
            assert!(
                out.status.success() && stderr.is_empty(),
                "{args:?}: {stderr}"
            );
            stdout
        };
        let d = dir.path().to_str().unwrap();
        for key in [
            "Dir::Etc::parts/d",
            "Dir::Etc::main/f",
            "Dir::Etc::sourcelist/f",
            "Dir::Etc::sourceparts/d",
            "Dir::Etc::preferences/f",
            "Dir::Etc::preferencesparts/d",
            "Dir::Etc::trustedparts/d",
            "Dir::Etc::netrc/f",
            "Dir::Etc::netrcparts/d",
            "Dir::State::lists/d",
            "Dir::Cache::archives/d",
            "Dir::Log/d",
        ] {
            let v = run(&["apt-config", "shell", "V", key]);
            assert!(v.starts_with(&format!("V='{d}/")), "{key}: {v}");
        }
        for (key, want) in [
            ("Dir::State::status/f", "/dev/null"),
            ("APT::Architecture", "amd64"),
            ("APT::Update::Error-Mode", "any"),
        ] {
            let v = run(&["apt-config", "shell", "V", key]);
            assert_eq!(v, format!("V='{want}'\n"), "{key}");
        }
        let targets = run(&[
            "apt-get",
            "indextargets",
            "--no-release-info",
            "--format",
            "$(SITE) $(RELEASE) $(COMPONENT)",
            "Identifier: Packages",
        ]);
        let mut targets: Vec<&str> = targets.lines().collect();
        targets.sort();
        targets.dedup();
        assert_eq!(
            targets,
            [
                "https://archive.ubuntu.com/ubuntu resolute main",
                "https://archive.ubuntu.com/ubuntu resolute universe",
                "https://archive.ubuntu.com/ubuntu resolute-updates main",
                "https://archive.ubuntu.com/ubuntu resolute-updates universe",
                "https://security.ubuntu.com/ubuntu resolute-security main",
                "https://security.ubuntu.com/ubuntu resolute-security universe",
            ]
        );
        let sources = fs::read_to_string(dir.path().join("etc/apt/sources.list")).unwrap();
        assert_eq!(sources.lines().count(), 3);
        assert!(sources.lines().all(|l| l.starts_with(
            "deb [arch=amd64 signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://"
        )));
        // A keyring path that would break the line is refused.
        for bad in ["/a b.gpg", "/a,b.gpg", "/a].gpg", "a.gpg"] {
            assert!(
                apt_root(dir.path(), &entry, Path::new(bad)).is_err(),
                "{bad}"
            );
        }
    }

    /// Packages cached by older versions are moved only as a fallback
    /// (`keep`), and deleted otherwise.
    #[test]
    fn old_debs_cache() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path().join("data"), dir.path().join("run")).unwrap();
        assert!(!old_debs(&paths, "ubuntu-26.04", true).unwrap());

        let images = paths.images_dir();
        let old_cache = || {
            ensure_private_dir(&images.join("debs/26.04")).unwrap();
            fs::write(images.join("debs/26.04/a_1_amd64.deb"), b"x").unwrap();
            ensure_private_dir(&images.join(".partial-debs-26.04/x")).unwrap();
        };
        // Fresh packages fetched: the old ones go.
        old_cache();
        assert!(!old_debs(&paths, "ubuntu-26.04", false).unwrap());
        assert!(!images.join("debs").exists());
        assert!(!images.join(".partial-debs-26.04").exists());

        // No network: the old ones move into place.
        old_cache();
        assert!(old_debs(&paths, "ubuntu-26.04", true).unwrap());
        let new = debs_dir(&paths, "ubuntu-26.04");
        assert!(new.join("a_1_amd64.deb").is_file());
        assert!(!images.join("debs").exists());
        assert!(!images.join(".partial-debs-26.04").exists());

        // An existing new cache is never replaced.
        old_cache();
        assert!(!old_debs(&paths, "ubuntu-26.04", true).unwrap());
        assert!(!images.join("debs").exists());
        assert!(new.join("a_1_amd64.deb").is_file());

        // Only Ubuntu had the old cache: other ids touch nothing.
        ensure_private_dir(&images.join("debs/13")).unwrap();
        assert!(!old_debs(&paths, "debian-13", true).unwrap());
        assert!(!old_debs(&paths, "debian-13", false).unwrap());
        assert!(images.join("debs/13").is_dir());
        assert!(!debs_dir(&paths, "debian-13").exists());
    }

    /// Agents get a clear refusal for images that are not pulled; an old
    /// cache counts only after a human pull moved it.
    #[test]
    fn agents_need_pulled_images() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path().join("data"), dir.path().join("run")).unwrap();
        let err = format!("{:#}", ensure_pulled(&paths, "ubuntu-26.04").unwrap_err());
        assert!(
            err.contains("not pulled; a human runs `stallo images pull ubuntu-26.04`"),
            "{err}"
        );
        assert!(ensure_pulled(&paths, "debian-13").is_err());
        let images = paths.images_dir();
        ensure_private_dir(&images.join("debs/26.04")).unwrap();
        fs::write(image_path(&paths, "ubuntu-26.04"), b"").unwrap();
        assert!(ensure_pulled(&paths, "ubuntu-26.04").is_err());
        ensure_private_dir(&debs_dir(&paths, "ubuntu-26.04")).unwrap();
        ensure_pulled(&paths, "ubuntu-26.04").unwrap();
        // A preinstalled guest agent: the image is all there is.
        assert!(ensure_pulled(&paths, "fedora-44").is_err());
        fs::write(image_path(&paths, "fedora-44"), b"").unwrap();
        ensure_pulled(&paths, "fedora-44").unwrap();
        // An ISO is cached as <id>.iso; a .qcow2 of that name does not count.
        let iso = find("fedora-44-workstation").unwrap();
        assert_eq!(cached_path(&paths, &iso), iso_path(&paths, &iso.id));
        fs::write(image_path(&paths, &iso.id), b"").unwrap();
        assert!(ensure_pulled(&paths, &iso.id).is_err());
        fs::write(iso_path(&paths, &iso.id), b"").unwrap();
        ensure_pulled(&paths, &iso.id).unwrap();
    }

    /// Fetches the guest-agent packages for real (network, about 20 MB of
    /// indexes for Ubuntu, 60 MB for Debian): `cargo test -- --ignored
    /// debs_live`.
    #[tokio::test]
    #[ignore = "downloads from the Ubuntu and Debian archives"]
    async fn debs_live() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path().join("data"), dir.path().join("run")).unwrap();
        ensure_private_dir(&paths.images_dir()).unwrap();
        for id in ["debian-13", "ubuntu-26.04"] {
            let entry = find(id).unwrap();
            pull_debs(&paths, &entry).await.unwrap();
            let names: Vec<String> = fs::read_dir(debs_dir(&paths, &entry.id))
                .unwrap()
                .map(|e| e.unwrap().file_name().into_string().unwrap())
                .collect();
            assert_eq!(names.len(), entry.debs.len(), "{names:?}");
        }
        // Only the debs (and the vendored keyring) are kept, not apt's
        // indexes.
        assert_eq!(fs::read_dir(paths.images_dir()).unwrap().count(), 3);
        let entry = find("ubuntu-26.04").unwrap();
        // A keyring that did not sign the archive: nothing is fetched.
        let mut wrong = entry.clone();
        wrong.id = "wrong-key".into();
        wrong.deb_keyring = Some("/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg".into());
        let err = pull_debs(&paths, &wrong).await.unwrap_err();
        assert!(format!("{err:#}").contains("apt-get update"), "{err:#}");
        assert!(!debs_dir(&paths, "wrong-key").exists());
        // Nor are apt's indexes left behind.
        assert!(!paths.images_dir().join(".partial-debs-wrong-key").exists());
    }

    /// S5: needs `qemu-img` (no VM is started).
    #[tokio::test]
    async fn refuses_backing_files_data_files_and_raw() {
        let dir = tempfile::tempdir().unwrap();
        let p = |n: &str| dir.path().join(n);
        let create = |args: &[&str]| {
            let ok = std::process::Command::new("qemu-img")
                .arg("create")
                .args(["-q", "-f", "qcow2"])
                .args(args)
                .status()
                .unwrap()
                .success();
            assert!(ok);
        };
        let s = |p: PathBuf| p.to_str().unwrap().to_owned();

        create(&[&s(p("base.qcow2")), "64M"]);
        let info = check_image(&p("base.qcow2")).await.unwrap();
        assert_eq!(info.virtual_size, 64 << 20);

        create(&[
            "-b",
            &s(p("base.qcow2")),
            "-F",
            "qcow2",
            &s(p("overlay.qcow2")),
        ]);
        let err = check_image(&p("overlay.qcow2")).await.unwrap_err();
        assert!(format!("{err:#}").contains("backing"), "{err:#}");

        create(&[
            "-o",
            &format!("data_file={}", s(p("data.raw"))),
            &s(p("ext.qcow2")),
            "64M",
        ]);
        let err = check_image(&p("ext.qcow2")).await.unwrap_err();
        assert!(format!("{err:#}").contains("data file"), "{err:#}");

        fs::write(p("raw.img"), vec![0u8; 1 << 20]).unwrap();
        assert!(check_image(&p("raw.img")).await.is_err());
    }

    /// Moving checksum lists (Ubuntu's `current/`) must be recently signed;
    /// release-pinned ones need not be. From the VALIDSIG lines gpgv gave
    /// for the real Ubuntu 26.04 and 24.04 lists (2026-10-15).
    #[test]
    fn moving_sums_signature_age() {
        let fpr = "D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81";
        let (day, now) = (86_400, 1_792_022_400); // 2026-10-15
        for (line, created) in [
            ("2026-09-29 1790640937 0 4 0 1 10 00", 1_790_640_937),
            ("2026-09-26 1790446992 0 4 0 1 10 00", 1_790_446_992),
        ] {
            let status = format!("[GNUPG:] VALIDSIG {fpr} {line} {fpr}\n");
            let mut fields = check_gpg_status(&status, fpr).unwrap();
            assert_eq!(sig_date(&fields).as_deref(), Some(&line[..10]));
            check_sig_age(&fields, now, MAX_SUMS_SIG_AGE_DAYS).unwrap();
            check_sig_age(&fields, created + 90 * day, MAX_SUMS_SIG_AGE_DAYS).unwrap();
            let stale =
                check_sig_age(&fields, created + 91 * day, MAX_SUMS_SIG_AGE_DAYS).unwrap_err();
            assert!(
                format!("{stale:#}").contains("91 days old (at most 90)"),
                "{stale:#}"
            );
            let future =
                check_sig_age(&fields, created - day - 1, MAX_SUMS_SIG_AGE_DAYS).unwrap_err();
            assert!(format!("{future:#}").contains("future"), "{future:#}");
            // A text signature (class 01, as a clearsigned list has) passes
            // the age check; only signed-image demands a binary one.
            fields[8] = "01".into();
            check_sig_age(&fields, now, MAX_SUMS_SIG_AGE_DAYS).unwrap();
            assert!(check_image_sig(&fields, now).is_err());
        }
        for (id, moving) in [
            ("ubuntu-26.04", true),
            ("ubuntu-24.04", true),
            ("fedora-44", false),
            ("arch", false),
            ("debian-13", false),
        ] {
            let e = find(id).unwrap();
            assert_eq!(e.moving, moving, "{id}");
            assert!(!moving || e.sums_url.as_deref().unwrap().contains("/current/"));
        }
    }

    /// Fetches the checksum lists of every `moving` entry (a few KB each):
    /// `cargo test -- --ignored moving_sums_live`. Their signatures verify
    /// and are recent enough today.
    #[tokio::test]
    #[ignore = "downloads checksum lists"]
    async fn moving_sums_live() {
        let dir = tempfile::tempdir().unwrap();
        for e in catalog().into_iter().filter(|e| e.moving) {
            let (text, validsig) = live_sums(&e, dir.path()).await;
            check_sig_age(&validsig, now_secs().unwrap(), MAX_SUMS_SIG_AGE_DAYS).unwrap();
            expected_sha256(&text, e.file(), e.sums_format.unwrap()).unwrap();
            eprintln!("{}: signed {}", e.id, sig_date(&validsig).unwrap());
        }
    }

    /// `images rm`: the image, its record, packages and leftovers go; other
    /// images stay; a symlink is refused, not followed.
    #[test]
    fn remove_image_files() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(
            fs::canonicalize(dir.path()).unwrap().join("data"),
            dir.path().join("run"),
        )
        .unwrap();
        assert!(!remove(&paths, "ubuntu-26.04").unwrap());
        let images = paths.images_dir();
        ensure_private_dir(&images).unwrap();
        for id in ["ubuntu-26.04", "ubuntu-24.04"] {
            fs::write(image_path(&paths, id), b"qcow2").unwrap();
            fs::set_permissions(image_path(&paths, id), fs::Permissions::from_mode(0o444)).unwrap();
            fs::write(record_path(&paths, id), b"sha256 = \"x\"\npulled_at = 1\n").unwrap();
            ensure_private_dir(&debs_dir(&paths, id)).unwrap();
            fs::write(debs_dir(&paths, id).join("a_1_amd64.deb"), b"x").unwrap();
            ensure_private_dir(&images.join(format!(".partial-{id}"))).unwrap();
            ensure_private_dir(&images.join(format!(".partial-debs-{id}"))).unwrap();
        }
        assert!(pulled(&paths, "ubuntu-26.04").is_some());
        ensure_private_dir(&images.join("debs/26.04")).unwrap();
        ensure_private_dir(&images.join("keys")).unwrap();
        assert!(remove(&paths, "ubuntu-26.04").unwrap());
        let mut left: Vec<_> = fs::read_dir(&images)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        assert_eq!(
            left,
            [
                ".partial-debs-ubuntu-24.04",
                ".partial-ubuntu-24.04",
                "keys",
                "ubuntu-24.04.debs",
                "ubuntu-24.04.qcow2",
                "ubuntu-24.04.toml",
            ]
        );
        assert!(!remove(&paths, "ubuntu-26.04").unwrap());
        assert!(remove(&paths, "../x").is_err());
        // A cached ISO and its record.
        let iso = "fedora-44-workstation";
        fs::write(iso_path(&paths, iso), b"iso").unwrap();
        fs::write(record_path(&paths, iso), b"sha256 = \"x\"\npulled_at = 1\n").unwrap();
        assert!(remove(&paths, iso).unwrap());
        assert!(!iso_path(&paths, iso).exists() && !record_path(&paths, iso).exists());
        // A planted symlink: refused, and its target stays.
        let target = dir.path().join("target");
        fs::write(&target, b"keep").unwrap();
        std::os::unix::fs::symlink(&target, image_path(&paths, "arch")).unwrap();
        assert!(remove(&paths, "arch").is_err());
        assert!(target.is_file());
    }

    /// Admission credits only the largest partial image, up to max_size.
    #[test]
    fn resumable_partial_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path().join("data"), dir.path().join("run")).unwrap();
        let entry = find("arch").unwrap();
        assert_eq!(resumable_bytes(&paths, &entry), 0);
        let work = paths.images_dir().join(".partial-arch");
        ensure_private_dir(&work).unwrap();
        let sized = |name: &str, len: u64| {
            fs::File::create(work.join(name))
                .unwrap()
                .set_len(len)
                .unwrap();
        };
        sized("a.part", 100);
        sized("b.part", 300);
        sized("b.sig", 900);
        assert_eq!(resumable_bytes(&paths, &entry), 300);
        sized("c.part", entry.max_size + 1);
        assert_eq!(resumable_bytes(&paths, &entry), entry.max_size);
        fs::remove_file(work.join("c.part")).unwrap();
        // A symlink to a large file does not count.
        std::os::unix::fs::symlink(work.join("b.sig"), work.join("d.part")).unwrap();
        assert_eq!(resumable_bytes(&paths, &entry), 300);
    }

    /// The backing file name, read from the qcow2 header.
    #[test]
    fn backing_file_from_header() {
        let dir = tempfile::tempdir().unwrap();
        let p = |n: &str| dir.path().join(n);
        let create = |args: &[&str]| {
            let ok = std::process::Command::new("qemu-img")
                .args(["create", "-q", "-f", "qcow2"])
                .args(args)
                .status()
                .unwrap()
                .success();
            assert!(ok);
        };
        let base = p("ubuntu-26.04.qcow2");
        create(&[base.to_str().unwrap(), "64M"]);
        assert_eq!(backing_file(&base).unwrap(), None);
        let disk = p("disk.qcow2");
        create(&[
            "-u",
            "-F",
            "qcow2",
            "-b",
            base.to_str().unwrap(),
            disk.to_str().unwrap(),
            "1G",
        ]);
        assert_eq!(backing_file(&disk).unwrap().as_deref(), base.to_str());
        assert_eq!(backing_file(&p("none.qcow2")).unwrap(), None);
        fs::write(p("raw.img"), vec![0u8; 4096]).unwrap();
        assert!(backing_file(&p("raw.img")).is_err());
        fs::write(p("short.img"), b"QFI").unwrap();
        assert!(backing_file(&p("short.img")).is_err());
        std::os::unix::fs::symlink(&disk, p("link.qcow2")).unwrap();
        assert!(backing_file(&p("link.qcow2")).is_err());
    }
}
