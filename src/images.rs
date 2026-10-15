//! Image catalog and verified downloads.
//!
//! A cloud image is used only after: the signature on `SHA256SUMS` verifies
//! against Ubuntu's keyring (`gpgv`) and comes from the pinned signing key,
//! the image's SHA-256 (computed here)
//! matches its line in `SHA256SUMS`, and `qemu-img info` shows a plain qcow2
//! with no backing file and no external data file. Cached images are
//! read-only and never replaced, because VM disks are overlays on them.
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
use std::os::unix::fs::PermissionsExt;
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
    /// The detached signature over the checksum list or the image.
    pub sig_url: Option<String>,
    pub sums_format: Option<SumsFormat>,
    /// The OpenPGP keyring that holds `signing_key`.
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
        for u in [&self.sums_url, &self.sig_url].into_iter().flatten() {
            ensure!(https(u), "{id}: {u:?} is not an https:// URL");
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
            (
                self.os,
                self.firmware,
                self.trust,
                self.sums_format,
                self.agent
            ) == (
                Os::Linux,
                Firmware::SecureBoot,
                Trust::SignedSums,
                Some(SumsFormat::Gnu),
                Agent::Deb
            ),
            "{id}: not supported yet: only Linux images with Secure Boot, signed GNU checksums and the guest agent as .debs"
        );
        Ok(())
    }

    /// The image's file name, as listed in the checksums.
    fn file(&self) -> &str {
        self.url.rsplit('/').next().unwrap_or_default()
    }
}

const CATALOG: &[&str] = &[include_str!("../catalog/ubuntu-26.04.toml")];

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

/// Whether the image and its guest-agent packages are cached.
pub fn is_cached(paths: &Paths, entry: &CatalogEntry) -> bool {
    image_path(paths, &entry.id).is_file() && debs_dir(paths, &entry.id).is_dir()
}

/// Refuses an image that is not cached: agents create VMs only from
/// images a human pulled.
pub fn ensure_pulled(paths: &Paths, id: &str) -> Result<()> {
    let entry = find(id)?;
    migrate_debs(paths, id)?;
    ensure!(
        is_cached(paths, &entry),
        "image {id} not pulled; a human runs `stallo images pull {id}`"
    );
    Ok(())
}

/// Moves guest-agent packages that older versions cached per Ubuntu
/// release (`debs/<release>/`) to `<id>.debs/`, so a host without
/// network keeps working, and drops an old partial download.
fn migrate_debs(paths: &Paths, id: &str) -> Result<()> {
    let root = paths.images_dir();
    let Some(release) = id.strip_prefix("ubuntu-") else {
        return Ok(());
    };
    if !root.is_dir() {
        return Ok(());
    }
    let old = root.join("debs").join(release);
    if old.is_dir() && !debs_dir(paths, id).exists() {
        fs::rename(&old, debs_dir(paths, id))?;
        fs::File::open(&root)?.sync_all()?;
        // Goes only once it is empty.
        let _ = fs::remove_dir(root.join("debs"));
    }
    safe_remove(&root, &root.join(format!(".partial-debs-{release}")))?;
    Ok(())
}

/// Downloads and verifies whatever of `entry` is not cached yet.
pub async fn pull(paths: &Paths, entry: &CatalogEntry) -> Result<()> {
    ensure_private_dir(&paths.images_dir())?;
    migrate_debs(paths, &entry.id)?;
    if !image_path(paths, &entry.id).is_file() {
        pull_image(paths, entry).await?;
    }
    if !debs_dir(paths, &entry.id).is_dir() {
        pull_debs(paths, entry).await?;
    }
    Ok(())
}

async fn pull_image(paths: &Paths, entry: &CatalogEntry) -> Result<()> {
    let root = paths.images_dir();
    let work = root.join(format!(".partial-{}", entry.id));
    ensure_private_dir(&work)?;

    // `validate` guarantees these for the only trust it accepts so far.
    let field = |f: &Option<String>| f.clone().context("incomplete catalog entry");
    let sums = work.join("SHA256SUMS");
    let sig = work.join("SHA256SUMS.gpg");
    for (url, f) in [
        (field(&entry.sums_url)?, &sums),
        (field(&entry.sig_url)?, &sig),
    ] {
        safe_remove(&root, f)?;
        download(&url, f, 1 << 20, false).await?;
    }
    let (keyring, key) = (field(&entry.keyring)?, field(&entry.signing_key)?);
    verify_signature(&keyring, &key, &sig, &sums)
        .await
        .context("signature check of SHA256SUMS failed")?;
    let expected = expected_sha256(&fs::read_to_string(&sums)?, entry.file())?;

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
    check_image(&image).await?;

    fs::set_permissions(&image, fs::Permissions::from_mode(0o444))?;
    fs::File::open(&image)?.sync_all()?;
    // A hard link fails if the target exists: a cached base image is never
    // replaced, because VM disks are overlays on it.
    fs::hard_link(&image, image_path(paths, &entry.id))?;
    fs::File::open(&root)?.sync_all()?;
    safe_remove(&root, &work)?;
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

/// Runs `gpgv` and requires exactly one valid signature by `fingerprint`
/// and no bad, expired or revoked one. gpgv's exit code alone accepts any
/// key in the keyring, revoked ones included.
async fn verify_signature(keyring: &str, fingerprint: &str, sig: &Path, data: &Path) -> Result<()> {
    let status = run_tool(
        Command::new("gpgv")
            .args(["--status-fd", "1", "--keyring", keyring])
            .arg(sig)
            .arg(data),
        Duration::from_secs(30),
    )
    .await?;
    check_gpg_status(&String::from_utf8_lossy(&status), fingerprint)
}

fn check_gpg_status(status: &str, fingerprint: &str) -> Result<()> {
    let mut valid = 0;
    for line in status.lines() {
        let mut words = line.split_whitespace();
        if words.next() != Some("[GNUPG:]") {
            continue;
        }
        match words.next() {
            Some("BADSIG" | "ERRSIG" | "EXPSIG" | "EXPKEYSIG" | "REVKEYSIG") => {
                bail!("gpgv reported: {line}")
            }
            // The last field of VALIDSIG is the primary key fingerprint.
            Some("VALIDSIG") if words.last() == Some(fingerprint) => valid += 1,
            Some("VALIDSIG") => bail!("signed by an unexpected key: {line}"),
            _ => {}
        }
    }
    ensure!(
        valid == 1,
        "expected one valid signature by {fingerprint}, found {valid}"
    );
    Ok(())
}

/// Finds the SHA-256 of `file` in a `SHA256SUMS` text (`<hex> *<name>`).
pub fn expected_sha256(sums: &str, file: &str) -> Result<String> {
    for line in sums.lines() {
        let Some((hash, name)) = line.split_once(' ') else {
            continue;
        };
        let name = name.trim_start_matches([' ', '*']);
        if name == file {
            ensure!(
                hash.len() == 64 && hash.bytes().all(|c| c.is_ascii_hexdigit()),
                "malformed SHA256SUMS line for {file}"
            );
            return Ok(hash.to_ascii_lowercase());
        }
    }
    bail!("{file} is not listed in SHA256SUMS")
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
        assert!(err(&bare).contains("not supported yet"));
        assert!(err(&bare[..3]).contains("no debs"));
        // HTTPS only.
        assert!(err(&[("url", Some(r#""http://example.com/a.img""#))]).contains("https"));
        assert!(err(&[("sums_url", Some(r#""ftp://example.com/S""#))]).contains("https"));
        // Full fingerprints only.
        for bad in ["7DB87C81", "d2eb44626fddc30b513d5bb71a5d6c4c7db87c81"] {
            let v = format!("{bad:?}");
            assert!(err(&[("signing_key", Some(&v))]).contains("40 upper-case"));
        }
        // Unknown fields and values are refused.
        assert!(entry_with(&[("release", Some(r#""26.04""#))]).is_err());
        assert!(entry_with(&[("os", Some(r#""macos""#))]).is_err());
        for (k, v) in [
            ("os", r#""windows""#),
            ("firmware", r#""uefi""#),
            ("sums_format", r#""bsd""#),
        ] {
            assert!(err(&[(k, Some(v))]).contains("not supported yet"), "{k}");
        }
    }

    #[test]
    fn sha256sums_lookup() {
        let h = "8800651811af9a85465ad1d552add729947bb16488dddb4a9b5305a3d97332b2";
        let sums = format!(
            "{} *resolute-server-cloudimg-amd64.manifest\n{h} *resolute-server-cloudimg-amd64.img\n",
            "1".repeat(64)
        );
        assert_eq!(
            expected_sha256(&sums, "resolute-server-cloudimg-amd64.img").unwrap(),
            h
        );
        assert!(expected_sha256(&sums, "resolute-server-cloudimg-amd64").is_err());
        assert!(expected_sha256("zz *a.img\n", "a.img").is_err());
        assert_eq!(
            expected_sha256(&format!("{h}  a.img\n"), "a.img").unwrap(),
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
        check_gpg_status(&good, fpr).unwrap();
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
    }

    /// Real gpgv against a throwaway key: a good signature passes; a wrong
    /// pinned key and a tampered file fail. Needs `gpg` and `gpgv`.
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
        fs::write(&data, b"abc *a.img\n").unwrap();
        let (sig_s, data_s) = (sig.to_str().unwrap(), data.to_str().unwrap());
        gpg(&["--detach-sign", "--output", sig_s, data_s]);

        let kr = keyring.to_str().unwrap();
        verify_signature(kr, &fpr, &sig, &data).await.unwrap();
        assert!(
            verify_signature(kr, &"0".repeat(40), &sig, &data)
                .await
                .is_err()
        );
        fs::write(&data, b"abd *a.img\n").unwrap();
        assert!(verify_signature(kr, &fpr, &sig, &data).await.is_err());
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

    /// Packages cached by older versions move to `<id>.debs/`.
    #[test]
    fn old_debs_cache_moves() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path().join("data"), dir.path().join("run")).unwrap();
        migrate_debs(&paths, "ubuntu-26.04").unwrap();

        let images = paths.images_dir();
        ensure_private_dir(&images.join("debs/26.04")).unwrap();
        fs::write(images.join("debs/26.04/a_1_amd64.deb"), b"x").unwrap();
        ensure_private_dir(&images.join(".partial-debs-26.04/x")).unwrap();
        migrate_debs(&paths, "ubuntu-26.04").unwrap();
        let new = debs_dir(&paths, "ubuntu-26.04");
        assert!(new.join("a_1_amd64.deb").is_file());
        assert!(!images.join("debs").exists());
        assert!(!images.join(".partial-debs-26.04").exists());

        // A newer cache wins; the old one stays untouched.
        ensure_private_dir(&images.join("debs/26.04")).unwrap();
        migrate_debs(&paths, "ubuntu-26.04").unwrap();
        assert!(images.join("debs/26.04").is_dir());
        assert!(new.join("a_1_amd64.deb").is_file());
    }

    /// Agents get a clear refusal for images that are not pulled; old
    /// caches count once moved.
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
        ensure_pulled(&paths, "ubuntu-26.04").unwrap();
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
