//! Image catalog and verified downloads.
//!
//! A cloud image is used only after: the signature on the checksum list
//! (detached or clearsigned) verifies against the catalog's keyring (`gpgv`)
//! and comes from the pinned signing key, the image's SHA-256 (computed
//! here) matches its line in the signed text, and `qemu-img info` shows a
//! plain qcow2 with no backing file and no external data file. With
//! `signed-image`, a detached signature over the image itself replaces the
//! checksum list, and it must be at most [`MAX_SIG_AGE_DAYS`] old. Cached
//! images are read-only and never replaced, because VM disks are overlays on
//! them.
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
use sha2::{Digest, Sha256};
use tokio::process::Command;

use crate::config::validate_image_id;
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
    pub os: Os,
    pub firmware: Firmware,
    /// The qcow2 image (HTTPS).
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
    /// The only keyring apt trusts for `deb_sources`.
    pub deb_keyring: Option<String>,
    /// Make the guest agent's SELinux domain permissive (see seed.rs): for
    /// guests where SELinux confines it, such as Fedora.
    #[serde(default)]
    pub qga_permissive: bool,
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
        if let Some(k) = &self.keyring {
            ensure!(
                (k.starts_with('/') && !k.contains(char::is_whitespace))
                    || KEYS.iter().any(|(name, _)| name == k),
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
            Agent::Preinstalled => ensure!(
                self.debs.is_empty() && self.deb_sources.is_empty() && self.deb_keyring.is_none(),
                "{id}: a preinstalled agent takes no debs, deb_sources or deb_keyring"
            ),
        }
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
        // `signed-by=` takes a comma-separated list: one keyring file only.
        if let Some(k) = &self.deb_keyring {
            ensure!(
                k.starts_with('/')
                    && plain(k)
                    && !k.contains(',')
                    && (k.ends_with(".gpg") || k.ends_with(".pgp")),
                "{id}: deb_keyring must be one absolute .gpg or .pgp path"
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
            self.os == Os::Linux && self.trust != Trust::Pinned,
            "{id}: not supported yet: only Linux images with signatures"
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
];

/// OpenPGP keyrings (binary) that catalog entries name in `keyring`. A
/// unit test pins the fingerprints in each.
const KEYS: &[(&str, &[u8])] = &[
    ("fedora.gpg", include_bytes!("../catalog/keys/fedora.gpg")),
    (
        "arch-boxes.gpg",
        include_bytes!("../catalog/keys/arch-boxes.gpg"),
    ),
];

/// The oldest signature `signed-image` accepts. Its URLs move to each new
/// build (Arch publishes one every two weeks), so an older signature means
/// a stale or replaying mirror.
///
/// A detached signature does not name the file: within this window, a
/// mirror could serve any image the same key signed (an older build, or
/// another image type) under the catalog's URL. TLS to the catalog's host
/// and this age limit are what bound that.
pub const MAX_SIG_AGE_DAYS: u64 = 90;

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

/// `<data>/images/<id>.debs/`.
pub fn debs_dir(paths: &Paths, id: &str) -> PathBuf {
    paths.images_dir().join(format!("{id}.debs"))
}

/// Whether the image and its guest-agent packages (if any) are cached.
pub fn is_cached(paths: &Paths, entry: &CatalogEntry) -> bool {
    image_path(paths, &entry.id).is_file()
        && (entry.agent == Agent::Preinstalled || debs_dir(paths, &entry.id).is_dir())
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

/// Downloads and verifies whatever of `entry` is not cached yet.
pub async fn pull(paths: &Paths, entry: &CatalogEntry) -> Result<()> {
    ensure_private_dir(&paths.images_dir())?;
    if !image_path(paths, &entry.id).is_file() {
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
    let image = match entry.trust {
        Trust::SignedSums => fetch_signed_sums(paths, entry, &work).await?,
        Trust::SignedImage => fetch_signed_image(paths, entry, &work).await?,
        Trust::Pinned => bail!("{}: pinned images are not supported yet", entry.id),
    };
    if let Err(e) = check_image(&image).await {
        // Otherwise the next pull would find the same file complete.
        safe_remove(&root, &image)?;
        return Err(e);
    }

    fs::set_permissions(&image, fs::Permissions::from_mode(0o444))?;
    fs::File::open(&image)?.sync_all()?;
    // A hard link fails if the target exists: a cached base image is never
    // replaced, because VM disks are overlays on it.
    fs::hard_link(&image, image_path(paths, &entry.id))?;
    fs::File::open(&root)?.sync_all()?;
    safe_remove(&root, &work)?;
    Ok(())
}

/// `validate` guarantees the fields each trust needs.
fn field(f: &Option<String>) -> Result<String> {
    f.clone().context("incomplete catalog entry")
}

/// Downloads the image into `work` and checks it against the signed
/// checksum list; returns its path.
async fn fetch_signed_sums(paths: &Paths, entry: &CatalogEntry, work: &Path) -> Result<PathBuf> {
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
    let text = signed_text(&keyring, &field(&entry.signing_key)?, &sums, sig, &signed)
        .await
        .context("signature check of the checksum list failed")?;
    let format = entry.sums_format.context("incomplete catalog entry")?;
    let expected = expected_sha256(&text, entry.file(), format)?;

    // Resume a partial download; skip it if a complete file is already
    // there. The name carries the expected hash, so a partial download of
    // an older upstream image is never resumed into a newer one.
    let image = work.join(format!("{expected}.part"));
    if !image.exists() || sha256_file(&image).await? != expected {
        tracing::info!("downloading {}", entry.url);
        download(&entry.url, &image, entry.max_size, true).await?;
        let actual = sha256_file(&image).await?;
        if actual != expected {
            safe_remove(&root, &image)?;
            bail!(
                "SHA-256 mismatch for {}: got {actual}, want {expected}",
                entry.file()
            );
        }
    }
    Ok(image)
}

/// Downloads the image into `work` and checks the detached signature over
/// it; returns its path.
///
/// No hash is known before the download, so the partial file is named
/// after the URL: a partial download from another catalog URL is never
/// resumed into this one. A moving URL can still serve a newer build
/// behind a partial download, and a mirror can be caught between image and
/// signature while it publishes: either fails the check, which deletes
/// both and tries once more from scratch. A failed download keeps the
/// partial file for the next pull.
async fn fetch_signed_image(paths: &Paths, entry: &CatalogEntry, work: &Path) -> Result<PathBuf> {
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
        // A complete file is not downloaded again (curl takes the server's
        // "range not satisfiable" as done).
        download(&entry.url, &image, entry.max_size, true).await?;
        let checked = async {
            let created = gpgv(&keyring, &fingerprint, &[&sig, &image], 600)
                .await?
                .context("gpgv gave no signature time in seconds")?;
            check_sig_age(created, now_secs()?)
        }
        .await
        .with_context(|| format!("signature check of {} failed", entry.url));
        match checked {
            Ok(()) => return Ok(image),
            Err(e) => {
                safe_remove(&root, &image)?;
                safe_remove(&root, &sig)?;
                if retried {
                    return Err(e);
                }
                tracing::warn!("{e:#}; downloading once more");
                retried = true;
            }
        }
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

/// Refuses a signature made more than [`MAX_SIG_AGE_DAYS`] before `now`
/// (both in seconds since the epoch).
fn check_sig_age(created: u64, now: u64) -> Result<()> {
    let days = now.saturating_sub(created) / 86_400;
    ensure!(
        days <= MAX_SIG_AGE_DAYS,
        "the signature is {days} days old (at most {MAX_SIG_AGE_DAYS}): the mirror looks stale"
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
    let conf = apt_root(work, entry)?;
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
/// read, and only `deb_keyring` is trusted for the catalog's sources.
fn apt_root(dir: &Path, entry: &CatalogEntry) -> Result<PathBuf> {
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
    let keyring = entry.deb_keyring.as_deref().context("no deb_keyring")?;
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

/// Runs `gpgv` on the checksum list `sums` and returns the signed text.
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
) -> Result<String> {
    let output = Path::new("--output");
    let (args, text) = match sig {
        Some(sig) => (vec![sig, sums], sums),
        None => (vec![output, out, sums], out),
    };
    gpgv(keyring, fingerprint, &args, 30).await?;
    Ok(fs::read_to_string(text)?)
}

/// Runs `gpgv` with `args` and checks its status (see
/// [`check_gpg_status`]); returns the signature's creation time.
async fn gpgv(
    keyring: &Path,
    fingerprint: &str,
    args: &[&Path],
    timeout: u64,
) -> Result<Option<u64>> {
    let mut cmd = Command::new("gpgv");
    cmd.args(["--status-fd", "1", "--keyring"])
        .arg(keyring)
        .args(args);
    let status = run_tool(&mut cmd, Duration::from_secs(timeout)).await?;
    check_gpg_status(&String::from_utf8_lossy(&status), fingerprint)
}

/// Requires exactly one valid signature by `fingerprint` and nothing bad;
/// returns its creation time (seconds since the epoch) if gpgv gave it in
/// seconds.
fn check_gpg_status(status: &str, fingerprint: &str) -> Result<Option<u64>> {
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
            // VALIDSIG <fpr> <date> <created> ... <primary fpr>: the last
            // field is the primary key. `created` is in seconds or, from
            // some GnuPG versions, ISO 8601 (then None).
            Some("VALIDSIG") => {
                let fields: Vec<&str> = words.collect();
                ensure!(
                    fields.last() == Some(&fingerprint),
                    "signed by an unexpected key: {line}"
                );
                valid.push(fields.get(2).and_then(|t| t.parse().ok()));
            }
            _ => {}
        }
    }
    match valid[..] {
        [created] => Ok(created),
        _ => bail!(
            "expected one valid signature by {fingerprint}, found {}",
            valid.len()
        ),
    }
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

/// Streams a file through SHA-256 on a blocking thread.
pub async fn sha256_file(path: &Path) -> Result<String> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || {
        let mut f = fs::File::open(&path)?;
        let mut hasher = Sha256::new();
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
        assert!(find("debian-13").is_err());
        assert!(find("../x").is_err());
    }

    /// The built-in entry with `edit` applied: a TOML value sets a key,
    /// `None` removes it.
    fn entry_with(edit: &[(&str, Option<&str>)]) -> Result<CatalogEntry> {
        let mut t: toml::Table = toml::from_str(CATALOG[0])?;
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
        ];
        // Valid but not handled yet.
        assert!(err(&pinned).contains("not supported yet"));
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
        ];
        assert!(err(&signed_image).contains("https"));
        let mut signed_image = signed_image.to_vec();
        signed_image[1] = ("sig_url", Some(r#""https://example.com/a.img.sig""#));
        entry_with(&signed_image).unwrap();
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
            // The fpr record right after each pub record.
            let mut found: Vec<&str> = listing
                .lines()
                .zip(listing.lines().skip(1))
                .filter(|(a, _)| a.starts_with("pub:"))
                .filter_map(|(_, b)| b.strip_prefix("fpr:::::::::"))
                .map(|f| f.trim_end_matches(':'))
                .collect();
            let mut pinned: Vec<&str> = catalog
                .iter()
                .filter(|e| e.keyring.as_deref() == Some(*name))
                .filter_map(|e| e.signing_key.as_deref())
                .collect();
            found.sort();
            pinned.sort();
            pinned.dedup();
            assert!(!pinned.is_empty(), "{name} is not used");
            assert_eq!(found, pinned, "{name}");
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
    async fn sha256_of_file() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("f");
        fs::write(&f, b"abc").unwrap();
        assert_eq!(
            sha256_file(&f).await.unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn gpg_status_is_pinned_to_one_key() {
        let fpr = "D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81";
        let good = format!(
            "[GNUPG:] NEWSIG\n[GNUPG:] GOODSIG 1A5D6C4C7DB87C81 UEC\n\
             [GNUPG:] VALIDSIG {fpr} 2026-09-29 1790640937 0 4 0 1 10 00 {fpr}\n"
        );
        assert_eq!(check_gpg_status(&good, fpr).unwrap(), Some(1790640937));
        // A signature time that is not in seconds is not one
        // (signed-image then refuses it).
        let iso = good.replace(" 1790640937 ", " 20260929T061537 ");
        assert_eq!(check_gpg_status(&iso, fpr).unwrap(), None);
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

    #[test]
    fn signature_age() {
        let day = 86_400;
        let now = 1_800_000_000;
        check_sig_age(now, now).unwrap();
        check_sig_age(now - 90 * day, now).unwrap();
        assert!(check_sig_age(now - 91 * day, now).is_err());
        // From the future (clock skew): not stale.
        check_sig_age(now + day, now).unwrap();
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
                signed_text(&keyring, &key, &data, sig.as_deref(), &out).await
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
        let created = gpgv(&keyring, &fpr, &[&image_sig, &image], 30)
            .await
            .unwrap()
            .unwrap();
        assert!(now_secs().unwrap().abs_diff(created) < 600, "{created}");
        // The signature over the checksum list is not one over the image.
        assert!(gpgv(&keyring, &fpr, &[&sig, &image], 30).await.is_err());
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
        let text = signed_text(&keyring, fpr, &sums, None, &out).await.unwrap();
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
            2,
            "only the image and the keys are left"
        );
    }

    /// The private apt root, checked offline with apt itself: every path
    /// resolves inside it, and apt sees the catalog's sources with the
    /// pinned keyring and nothing of the host's (which may have PPAs).
    #[test]
    fn apt_root_is_private() {
        let dir = tempfile::tempdir().unwrap();
        let entry = find("ubuntu-26.04").unwrap();
        let conf = apt_root(dir.path(), &entry).unwrap();
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
    }

    /// Fetches the guest-agent packages for real (network, about 20 MB of
    /// indexes): `cargo test -- --ignored debs_live`.
    #[tokio::test]
    #[ignore = "downloads from the Ubuntu archive"]
    async fn debs_live() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path().join("data"), dir.path().join("run")).unwrap();
        ensure_private_dir(&paths.images_dir()).unwrap();
        let entry = find("ubuntu-26.04").unwrap();
        pull_debs(&paths, &entry).await.unwrap();
        let names: Vec<String> = fs::read_dir(debs_dir(&paths, &entry.id))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names.len(), entry.debs.len(), "{names:?}");
        // Only the debs are kept, not apt's indexes.
        assert_eq!(fs::read_dir(paths.images_dir()).unwrap().count(), 1);
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
}
