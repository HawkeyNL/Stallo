//! Image catalog and verified downloads.
//!
//! A cloud image is used only after: the signature on `SHA256SUMS` verifies
//! against Ubuntu's keyring (`gpgv`) and comes from the pinned signing key,
//! the image's SHA-256 (computed here)
//! matches its line in `SHA256SUMS`, and `qemu-img info` shows a plain qcow2
//! with no backing file and no external data file. Cached images are
//! read-only and never replaced, because VM disks are overlays on them.
//!
//! TLS and OpenPGP stay with `curl` and `gpgv`, which Ubuntu patches; every
//! subprocess gets fixed arguments, never a shell.
//!
//! Callers serialise pulls (the daemon holds one lock for all of them).

use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::process::Command;

use crate::config::validate_image_id;
use crate::paths::{Paths, ensure_private_dir, safe_remove};
use crate::run_tool;

/// One catalog entry (`catalog/<id>.toml`, compiled in).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogEntry {
    pub id: String,
    pub name: String,
    /// Ubuntu release of the guest, e.g. `26.04`.
    pub release: String,
    pub base_url: String,
    pub file: String,
    pub keyring: String,
    /// Fingerprint of the primary key that must sign `SHA256SUMS`.
    pub signing_key: String,
    /// Packages the guest needs for the guest agent but lacks.
    pub debs: Vec<String>,
}

const CATALOG: &[&str] = &[include_str!("../catalog/ubuntu-26.04.toml")];

/// All catalog entries.
pub fn catalog() -> Vec<CatalogEntry> {
    CATALOG
        .iter()
        .map(|text| toml::from_str(text).expect("built-in catalog is valid"))
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

/// `<data>/images/debs/<release>/`.
pub fn debs_dir(paths: &Paths, release: &str) -> PathBuf {
    paths.images_dir().join("debs").join(release)
}

/// Whether the image and its guest-agent packages are cached.
pub fn is_cached(paths: &Paths, entry: &CatalogEntry) -> bool {
    image_path(paths, &entry.id).is_file() && debs_dir(paths, &entry.release).is_dir()
}

/// Downloads and verifies whatever of `entry` is not cached yet.
pub async fn pull(paths: &Paths, entry: &CatalogEntry) -> Result<()> {
    ensure_private_dir(&paths.images_dir())?;
    if !image_path(paths, &entry.id).is_file() {
        pull_image(paths, entry).await?;
    }
    if !debs_dir(paths, &entry.release).is_dir() {
        pull_debs(paths, entry).await?;
    }
    Ok(())
}

async fn pull_image(paths: &Paths, entry: &CatalogEntry) -> Result<()> {
    let root = paths.images_dir();
    let work = root.join(format!(".partial-{}", entry.id));
    ensure_private_dir(&work)?;

    let sums = work.join("SHA256SUMS");
    let sig = work.join("SHA256SUMS.gpg");
    for f in [&sums, &sig] {
        safe_remove(&root, f)?;
        let name = f.file_name().unwrap().to_str().unwrap();
        download(&format!("{}{name}", entry.base_url), f, "1M", false).await?;
    }
    verify_signature(&entry.keyring, &entry.signing_key, &sig, &sums)
        .await
        .context("signature check of SHA256SUMS failed")?;
    let expected = expected_sha256(&fs::read_to_string(&sums)?, &entry.file)?;

    // Resume a partial download; skip it if a complete file is already
    // there. The name carries the expected hash, so a partial download of
    // an older upstream image is never resumed into a newer one.
    let image = work.join(format!("{expected}.part"));
    if !image.exists() || sha256_file(&image).await? != expected {
        tracing::info!("downloading {}{}", entry.base_url, entry.file);
        let url = format!("{}{}", entry.base_url, entry.file);
        download(&url, &image, "4G", true).await?;
        let actual = sha256_file(&image).await?;
        if actual != expected {
            safe_remove(&root, &image)?;
            bail!(
                "SHA-256 mismatch for {}: got {actual}, want {expected}",
                entry.file
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

/// `apt-get download` checks every package against the host's signed apt
/// indexes; no root is needed. This only fits because guest and host run
/// the same Ubuntu release.
async fn pull_debs(paths: &Paths, entry: &CatalogEntry) -> Result<()> {
    let host = host_release(&fs::read_to_string("/etc/os-release")?);
    ensure!(
        host.as_deref() == Some(entry.release.as_str()),
        "guest-agent packages for Ubuntu {} can only be fetched on an Ubuntu {} host",
        entry.release,
        entry.release
    );
    let root = paths.images_dir();
    let final_dir = debs_dir(paths, &entry.release);
    let work = root.join(format!(".partial-debs-{}", entry.release));
    safe_remove(&root, &work)?;
    ensure_private_dir(&work)?;
    // The guest image is amd64, whatever the host architecture.
    run_tool(
        Command::new("apt-get")
            .arg("download")
            .args(entry.debs.iter().map(|d| format!("{d}:amd64")))
            .current_dir(&work),
        Duration::from_secs(600),
    )
    .await
    .context("apt-get download of the guest-agent packages failed")?;
    for pkg in &entry.debs {
        let found = fs::read_dir(&work)?
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with(&format!("{pkg}_")) && n.ends_with(".deb"))
            })
            .count();
        ensure!(found == 1, "expected one .deb for {pkg}, found {found}");
    }
    ensure_private_dir(final_dir.parent().unwrap())?;
    fs::rename(&work, &final_dir)?;
    Ok(())
}

/// Fetches `url` over HTTPS only (redirects included), with a size cap and
/// stall detection.
async fn download(url: &str, dest: &Path, max_size: &str, resume: bool) -> Result<()> {
    let mut cmd = Command::new("curl");
    // `-q` must come first: it stops curl from reading ~/.curlrc.
    cmd.args(["-q", "--proto", "=https", "--tlsv1.2", "--fail"])
        .args(["--silent", "--show-error", "--location", "--retry", "3"])
        .args(["--connect-timeout", "30", "--speed-limit", "10240"])
        .args(["--speed-time", "60", "--max-filesize", max_size]);
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

/// `VERSION_ID` from `/etc/os-release`, if this is Ubuntu.
fn host_release(os_release: &str) -> Option<String> {
    let field = |key: &str| {
        os_release.lines().find_map(|l| {
            l.strip_prefix(key)
                .and_then(|v| v.strip_prefix('='))
                .map(|v| v.trim_matches('"').to_owned())
        })
    };
    (field("ID").as_deref() == Some("ubuntu"))
        .then(|| field("VERSION_ID"))
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_parses() {
        let e = find("ubuntu-26.04").unwrap();
        assert_eq!(e.release, "26.04");
        assert!(e.base_url.starts_with("https://") && e.base_url.ends_with('/'));
        assert!(e.debs.contains(&"qemu-guest-agent".to_owned()));
        assert!(find("debian-13").is_err());
        assert!(find("../x").is_err());
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

    #[test]
    fn os_release() {
        let text = "PRETTY_NAME=\"Ubuntu 26.04.1 LTS\"\nVERSION_ID=\"26.04\"\nID=ubuntu\n";
        assert_eq!(host_release(text).as_deref(), Some("26.04"));
        assert_eq!(host_release("ID=debian\nVERSION_ID=\"13\"\n"), None);
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
