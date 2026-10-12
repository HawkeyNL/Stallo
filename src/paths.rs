//! Directory layout, socket path checks and the one function that deletes
//! things (`safe_remove`).

use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::config::MAX_NAME_LEN;

/// `sun_path` is 108 bytes on Linux, including the trailing NUL.
const MAX_SOCKET_PATH: usize = 107;

/// The longest socket file name used inside a per-VM runtime directory.
const LONGEST_VM_SOCKET: &str = "passt.sock";

/// Where the daemon keeps its data and runtime files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    /// VM definitions, disks and cached images.
    pub data: PathBuf,
    /// Sockets and other per-boot files (tmpfs).
    pub runtime: PathBuf,
}

impl Paths {
    /// Dev mode: everything under the current user's home and runtime dir.
    pub fn dev() -> Result<Self> {
        let home = env_dir("HOME")?;
        let runtime = env_dir("XDG_RUNTIME_DIR")?;
        Self::new(
            home.join(".local/share/stallo-dev"),
            runtime.join("stallo-dev"),
        )
    }

    /// Production mode: system directories owned by the `stallo` user.
    pub fn production() -> Result<Self> {
        Self::new("/var/lib/stallo".into(), "/run/stallo".into())
    }

    /// Builds a layout from explicit directories. Both must be absolute, and
    /// the longest per-VM socket path must fit in `sun_path`.
    pub fn new(data: PathBuf, runtime: PathBuf) -> Result<Self> {
        if !data.is_absolute() || !runtime.is_absolute() {
            bail!("data and runtime directories must be absolute paths");
        }
        let paths = Self { data, runtime };
        let longest = paths
            .vm_runtime_dir(&"a".repeat(MAX_NAME_LEN))
            .join(LONGEST_VM_SOCKET);
        check_socket_path(&longest)
            .context("runtime directory path is too long for Unix sockets")?;
        Ok(paths)
    }

    /// Creates both directories (mode 0700) and returns the layout with
    /// canonical paths, which `safe_remove` requires of its root. Called
    /// once at daemon start.
    pub fn prepare(&self) -> Result<Self> {
        ensure_private_dir(&self.data)?;
        ensure_private_dir(&self.runtime)?;
        Self::new(
            fs::canonicalize(&self.data)?,
            fs::canonicalize(&self.runtime)?,
        )
    }

    pub fn api_socket(&self) -> PathBuf {
        self.runtime.join("api.sock")
    }

    pub fn config_file(&self) -> PathBuf {
        self.data.join("stallod.toml")
    }

    pub fn vms_dir(&self) -> PathBuf {
        self.data.join("vms")
    }

    /// `<data>/vms/<name>`. `name` must already be validated.
    pub fn vm_dir(&self, name: &str) -> PathBuf {
        self.vms_dir().join(name)
    }

    /// `<data>/audit`: the audit logs (outlive the VMs).
    pub fn audit_dir(&self) -> PathBuf {
        self.data.join("audit")
    }

    pub fn images_dir(&self) -> PathBuf {
        self.data.join("images")
    }

    pub fn vms_runtime_dir(&self) -> PathBuf {
        self.runtime.join("vms")
    }

    /// `<runtime>/vms/<name>`: QMP and QGA sockets, mode 0700.
    pub fn vm_runtime_dir(&self, name: &str) -> PathBuf {
        self.vms_runtime_dir().join(name)
    }
}

fn env_dir(var: &str) -> Result<PathBuf> {
    let dir = PathBuf::from(std::env::var_os(var).with_context(|| format!("{var} is not set"))?);
    if !dir.is_absolute() {
        bail!("{var} must be an absolute path");
    }
    Ok(dir)
}

/// Fails if `path` does not fit in a Unix socket address.
pub fn check_socket_path(path: &Path) -> Result<()> {
    let len = path.as_os_str().len();
    if len > MAX_SOCKET_PATH {
        bail!(
            "socket path {} is {len} bytes; the limit is {MAX_SOCKET_PATH}",
            path.display()
        );
    }
    Ok(())
}

/// Creates `dir` (and missing parents) and makes `dir` itself mode 0700.
/// Refuses a symlink. `chmod` fails unless we own the directory.
pub fn ensure_private_dir(dir: &Path) -> Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("cannot create {}", dir.display()))?;
    let meta = fs::symlink_metadata(dir)?;
    if !meta.is_dir() {
        bail!("{} is not a directory", dir.display());
    }
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("cannot chmod 0700 {}", dir.display()))?;
    Ok(())
}

/// Removes `target` (a file or a whole directory tree) only if it lies
/// strictly inside `root`.
///
/// Refuses relative paths, `..`, `root` itself, a non-canonical `root` (a
/// symlink anywhere in it), and a symlink at `target` or at any directory
/// between `root` and `target`. A missing `target` is not an error.
/// `remove_dir_all` does not follow symlinks inside the tree.
///
/// Every delete in Stallo goes through this function.
///
/// Known gap: a parent could be swapped for a symlink between the check and
/// the delete. Only the daemon's own UID can write there, and it can already
/// delete anything in the data dir, so this is accepted. If QEMU ever runs
/// under a separate UID with write access, switch to `openat2` with
/// `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`.
pub fn safe_remove(root: &Path, target: &Path) -> io::Result<()> {
    let refuse = |why: &str| {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "refusing to remove {} (root {}): {why}",
                target.display(),
                root.display()
            ),
        ))
    };
    if !root.is_absolute() || !target.is_absolute() {
        return refuse("paths must be absolute");
    }
    // Never operate on `/` or a top-level directory such as `/home`.
    if root
        .components()
        .filter(|c| matches!(c, Component::Normal(_)))
        .count()
        < 2
    {
        return refuse("root is too close to /");
    }
    let Ok(rel) = target.strip_prefix(root) else {
        return refuse("outside root");
    };
    if rel.as_os_str().is_empty() {
        return refuse("target is the root itself");
    }
    if !rel.components().all(|c| matches!(c, Component::Normal(_))) {
        return refuse("path has '..' or '.' components");
    }
    if fs::canonicalize(root)? != root {
        return refuse("root is not canonical");
    }
    let mut cur = root.to_path_buf();
    let mut meta = None;
    for c in rel.components() {
        cur.push(c);
        match fs::symlink_metadata(&cur) {
            Ok(m) if m.file_type().is_symlink() => return refuse("symlink in path"),
            Ok(m) => meta = Some(m),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        }
    }
    match meta {
        Some(m) if m.is_dir() => fs::remove_dir_all(target),
        _ => fs::remove_file(target),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn root() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        (dir, root)
    }

    #[test]
    fn removes_a_tree_inside_root() {
        let (_t, root) = root();
        let vm = root.join("vms/dev");
        fs::create_dir_all(vm.join("sub")).unwrap();
        fs::write(vm.join("sub/file"), b"x").unwrap();
        safe_remove(&root, &vm).unwrap();
        assert!(!vm.exists());
        assert!(root.join("vms").exists());
    }

    #[test]
    fn removes_a_file_and_ignores_missing_targets() {
        let (_t, root) = root();
        let f = root.join("file");
        fs::write(&f, b"x").unwrap();
        safe_remove(&root, &f).unwrap();
        assert!(!f.exists());
        safe_remove(&root, &root.join("missing/also")).unwrap();
    }

    #[test]
    fn refuses_dotdot_relative_outside_and_root() {
        let (_t, root) = root();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("keep"), b"x").unwrap();
        for target in [
            root.join("vms/../.."),
            root.join(".."),
            PathBuf::from("vms/dev"),
            outside.path().to_path_buf(),
            PathBuf::from("/"),
            root.clone(),
        ] {
            assert!(safe_remove(&root, &target).is_err(), "{}", target.display());
        }
        assert!(outside.path().join("keep").exists());
    }

    #[test]
    fn symlink_inside_tree_is_removed_not_followed() {
        let (_t, root) = root();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("keep"), b"x").unwrap();
        let vm = root.join("vm");
        fs::create_dir(&vm).unwrap();
        symlink(outside.path(), vm.join("link")).unwrap();
        safe_remove(&root, &vm).unwrap();
        assert!(!vm.exists());
        assert!(outside.path().join("keep").exists());
    }

    #[test]
    fn refuses_bad_roots_and_sibling_prefixes() {
        let (_t, root) = root();
        let sibling = PathBuf::from(format!("{}x", root.display()));
        fs::create_dir(&sibling).unwrap();
        fs::write(sibling.join("keep"), b"x").unwrap();
        assert!(safe_remove(&root, &sibling.join("keep")).is_err());
        assert!(sibling.join("keep").exists());
        fs::remove_dir_all(&sibling).unwrap();

        assert!(safe_remove(Path::new("/"), Path::new("/tmp/x")).is_err());
        assert!(safe_remove(Path::new("/tmp"), Path::new("/tmp/x")).is_err());
        assert!(safe_remove(Path::new("rel/root"), Path::new("rel/root/x")).is_err());
        let dotted = root.join("a/..");
        assert!(safe_remove(&dotted, &dotted.join("x")).is_err());
        let missing = root.join("missing");
        assert!(safe_remove(&missing, &missing.join("x")).is_err());
    }

    #[test]
    fn prepare_canonicalizes() {
        let (_t, root) = root();
        fs::create_dir(root.join("real")).unwrap();
        symlink(root.join("real"), root.join("alias")).unwrap();
        let paths = Paths::new(root.join("alias/data"), root.join("alias/run"))
            .unwrap()
            .prepare()
            .unwrap();
        assert_eq!(paths.data, root.join("real/data"));
        assert_eq!(paths.runtime, root.join("real/run"));
    }

    #[test]
    fn refuses_symlinks() {
        let (_t, root) = root();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("keep"), b"x").unwrap();

        // Symlink as the target, pointing at / and at a real directory.
        symlink("/", root.join("to-root")).unwrap();
        assert!(safe_remove(&root, &root.join("to-root")).is_err());
        symlink(outside.path(), root.join("link")).unwrap();
        assert!(safe_remove(&root, &root.join("link")).is_err());

        // Symlinked parent directory.
        assert!(safe_remove(&root, &root.join("link/keep")).is_err());
        assert!(outside.path().join("keep").exists());

        // Root given through a symlink.
        let alias = root.join("alias");
        fs::create_dir(root.join("real")).unwrap();
        fs::write(root.join("real/f"), b"x").unwrap();
        symlink(root.join("real"), &alias).unwrap();
        assert!(safe_remove(&alias, &alias.join("f")).is_err());
        assert!(root.join("real/f").exists());
    }

    #[test]
    fn socket_path_limit() {
        assert!(check_socket_path(Path::new(&format!("/{}", "a".repeat(106)))).is_ok());
        assert!(check_socket_path(Path::new(&format!("/{}", "a".repeat(107)))).is_err());
        assert!(Paths::new("/d".into(), format!("/{}", "r".repeat(80)).into()).is_err());
        assert!(Paths::new("/d".into(), "/run/user/1000/stallo-dev".into()).is_ok());
        assert!(Paths::new("d".into(), "/r".into()).is_err());
    }

    #[test]
    fn private_dir_is_0700() {
        let (_t, root) = root();
        let d = root.join("a/b");
        ensure_private_dir(&d).unwrap();
        fs::set_permissions(&d, fs::Permissions::from_mode(0o755)).unwrap();
        ensure_private_dir(&d).unwrap();
        let mode = fs::metadata(&d).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        symlink(&d, root.join("l")).unwrap();
        assert!(ensure_private_dir(&root.join("l")).is_err());
    }
}
