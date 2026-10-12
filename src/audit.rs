//! Audit log: one JSON line per API call, in `<data>/audit/<vm>.jsonl` for
//! calls on an existing VM and `<data>/audit/_daemon.jsonl` for the rest.
//! The log lives outside the VM directory, so it outlives `stallo rm`.
//!
//! A line holds who (peer UID and PID, `via`), what (operation, argument
//! **sizes**, `argv[0]` for exec), the result size, the duration and
//! ok/error. It never holds content: no typed text, file data, file paths,
//! exec arguments after `argv[0]`, stdin or error messages (which can echo
//! guest data).

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Mutex;

use serde::Serialize;

use crate::api::{Request, Via};

/// The log for calls that do not name an existing VM (`_` is not allowed
/// in VM names).
pub const DAEMON: &str = "_daemon";
/// The log rotates at this size; three old files are kept.
const ROTATE_BYTES: u64 = 10 << 20;
const KEEP: u32 = 3;

/// One audit line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Entry {
    /// Milliseconds since the Unix epoch.
    pub time_ms: u64,
    pub uid: u32,
    pub pid: Option<i32>,
    pub via: Via,
    pub op: &'static str,
    /// Sizes in bytes (or counts) of the arguments that carry content.
    pub args: BTreeMap<&'static str, u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub argv0: Option<String>,
    pub result_bytes: u64,
    pub ms: u64,
    pub ok: bool,
}

/// The operation name, the VM it targets (if any), the sizes of its
/// content-carrying arguments and, for exec, `argv[0]`.
pub type Described<'a> = (
    &'static str,
    Option<&'a str>,
    Vec<(&'static str, u64)>,
    Option<String>,
);

/// Describes `r` for the audit log; see [`Described`].
pub fn describe(r: &Request) -> Described<'_> {
    let len = |s: &str| s.len() as u64;
    match r {
        Request::New { name, .. } => ("new", Some(name), vec![], None),
        Request::List => ("list", None, vec![], None),
        Request::Start { name, .. } => ("start", Some(name), vec![], None),
        Request::Stop { name, .. } => ("stop", Some(name), vec![], None),
        Request::Exec {
            name,
            argv,
            stdin,
            admin,
            ..
        } => (
            "exec",
            Some(name),
            vec![
                ("admin", u64::from(*admin)),
                ("argv", argv.len() as u64),
                ("argv_bytes", argv.iter().map(|a| len(a)).sum()),
                ("stdin", stdin.as_deref().map_or(0, len)),
            ],
            argv.first().map(|a| cut(a, 256)),
        ),
        Request::FileRead {
            name, path, admin, ..
        } => (
            "file_read",
            Some(name),
            vec![("admin", u64::from(*admin)), ("path", len(path))],
            None,
        ),
        Request::FileWrite {
            name,
            path,
            data_base64,
            admin,
            ..
        } => {
            let pad = data_base64.bytes().rev().take_while(|&b| b == b'=').count();
            let data = (len(data_base64) / 4 * 3).saturating_sub(pad as u64);
            (
                "file_write",
                Some(name),
                vec![
                    ("admin", u64::from(*admin)),
                    ("data", data),
                    ("path", len(path)),
                ],
                None,
            )
        }
        Request::Rm { name } => ("rm", Some(name), vec![], None),
        Request::Info { name } => ("info", Some(name), vec![], None),
        Request::Reset { name } => ("reset", Some(name), vec![], None),
        Request::Screenshot { name } => ("screenshot", Some(name), vec![], None),
        Request::WaitForScreen { name, .. } => ("wait_for_screen", Some(name), vec![], None),
        Request::MouseMove { name, .. } => ("mouse_move", Some(name), vec![], None),
        Request::Click { name, .. } => ("click", Some(name), vec![], None),
        Request::Drag { name, .. } => ("drag", Some(name), vec![], None),
        Request::Scroll { name, .. } => ("scroll", Some(name), vec![], None),
        Request::TypeText { name, text } => {
            ("type_text", Some(name), vec![("text", len(text))], None)
        }
        Request::Key { name, keys } => ("key", Some(name), vec![("keys", len(keys))], None),
        Request::Resume { name } => ("resume", Some(name), vec![], None),
        Request::Snapshot { name, tag } => (
            "snapshot",
            Some(name),
            vec![("tag", tag.as_deref().map_or(0, len))],
            None,
        ),
        Request::Snapshots { name } => ("snapshots", Some(name), vec![], None),
        Request::Restore { name, tag } => (
            "restore",
            Some(name),
            vec![("tag", tag.as_deref().map_or(0, len))],
            None,
        ),
        Request::SnapshotDelete { name, tag } => {
            ("snapshot_delete", Some(name), vec![("tag", len(tag))], None)
        }
        Request::SetAgent { name, on } => ("agent", Some(name), vec![("on", u64::from(*on))], None),
        Request::Host => ("host", None, vec![], None),
        Request::Images => ("images", None, vec![], None),
        Request::Pull { .. } => ("pull", None, vec![], None),
    }
}

/// At most this much of `s`, cut at a character boundary.
fn cut(s: &str, max: usize) -> String {
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_owned()
}

/// Serialises rotation across all logs.
static LOCK: Mutex<()> = Mutex::new(());

/// Opens `<dir>/<log>.jsonl` for appending (mode 0600, never through a
/// symlink), rotating it first at 10 MiB. Opened before the call runs, so
/// an agent call can be refused when it cannot be logged. Blocking.
pub fn open(dir: &Path, log: &str) -> io::Result<fs::File> {
    open_at(dir, log, ROTATE_BYTES)
}

fn open_at(dir: &Path, log: &str, rotate: u64) -> io::Result<fs::File> {
    let name = |i: u32| match i {
        0 => format!("{log}.jsonl"),
        i => format!("{log}.jsonl.{i}"),
    };
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let path = dir.join(name(0));
    if fs::symlink_metadata(&path).is_ok_and(|m| m.len() >= rotate) {
        for i in (0..KEEP).rev() {
            let from = dir.join(name(i));
            if from.exists() {
                fs::rename(&from, dir.join(name(i + 1)))?;
            }
        }
    }
    fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
}

/// Appends `entry` as one line (one `write`, so lines never interleave).
pub fn write(file: &mut fs::File, entry: &Entry) -> io::Result<()> {
    let mut line = serde_json::to_vec(entry)?;
    line.push(b'\n');
    file.write_all(&line)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(r: &Request) -> String {
        let (op, _, args, argv0) = describe(r);
        let e = Entry {
            time_ms: 1,
            uid: 1000,
            pid: Some(42),
            via: Via::Mcp,
            op,
            args: args.into_iter().collect(),
            argv0,
            result_bytes: 7,
            ms: 3,
            ok: true,
        };
        serde_json::to_string(&e).unwrap()
    }

    /// S9: content never reaches the log, sizes do.
    #[test]
    fn redaction() {
        use base64::Engine;
        let secret = "hunter2-secret";
        let cases = [
            Request::TypeText {
                name: "dev".into(),
                text: secret.into(),
            },
            Request::Exec {
                name: "dev".into(),
                argv: vec!["sh".into(), "-c".into(), format!("echo {secret}")],
                admin: false,
                timeout_s: None,
                stdin: Some(secret.into()),
            },
            Request::FileWrite {
                name: "dev".into(),
                path: format!("/home/{secret}"),
                data_base64: base64::engine::general_purpose::STANDARD.encode(secret),
                append: false,
                admin: false,
            },
            Request::FileRead {
                name: "dev".into(),
                path: format!("/{secret}"),
                offset: 0,
                max_bytes: None,
                admin: true,
            },
            Request::Key {
                name: "dev".into(),
                keys: secret.into(),
            },
        ];
        for r in &cases {
            let line = entry(r);
            assert!(!line.contains("hunter2"), "{line}");
            assert!(!line.contains("aHVudGVy"), "{line}");
        }
        let exec = entry(&cases[1]);
        assert!(exec.contains(r#""argv0":"sh""#), "{exec}");
        assert!(
            exec.contains(r#""argv":3"#) && exec.contains(r#""stdin":14"#),
            "{exec}"
        );
        assert!(entry(&cases[0]).contains(r#""text":14"#));
        assert!(entry(&cases[2]).contains(r#""data":14"#));
        let long = Request::Exec {
            name: "dev".into(),
            argv: vec!["é".repeat(300)],
            admin: true,
            timeout_s: None,
            stdin: None,
        };
        let (_, _, args, argv0) = describe(&long);
        assert_eq!(argv0.unwrap().len(), 256);
        assert!(args.contains(&("admin", 1)));
    }

    #[test]
    fn appends_and_rotates() {
        let dir = tempfile::tempdir().unwrap();
        let (op, _, args, argv0) = describe(&Request::Screenshot { name: "dev".into() });
        let e = Entry {
            time_ms: 1,
            uid: 1000,
            pid: None,
            via: Via::Cli,
            op,
            args: args.into_iter().collect(),
            argv0,
            result_bytes: 0,
            ms: 0,
            ok: false,
        };
        for _ in 0..12 {
            write(&mut open_at(dir.path(), "dev", 300).unwrap(), &e).unwrap();
        }
        use std::os::unix::fs::PermissionsExt;
        let file = dir.path().join("dev.jsonl");
        let meta = fs::metadata(&file).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert!(meta.len() < 300 + 200);
        for i in 1..=KEEP {
            assert!(dir.path().join(format!("dev.jsonl.{i}")).exists(), "{i}");
        }
        assert!(!dir.path().join(format!("dev.jsonl.{}", KEEP + 1)).exists());
        let text = fs::read_to_string(&file).unwrap();
        let first: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(first["op"], "screenshot");
        assert_eq!(first["via"], "cli");

        // Never written through a symlink.
        fs::remove_file(&file).unwrap();
        std::os::unix::fs::symlink("/dev/null", &file).unwrap();
        assert!(open_at(dir.path(), "dev", 300).is_err());
    }
}
