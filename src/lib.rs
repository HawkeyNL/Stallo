//! Stallo: an agent-first VM manager for Ubuntu on QEMU/KVM.
//!
//! `stallod` (the daemon) owns every VM; `stallo` (the CLI) talks to it over
//! a Unix socket.

pub mod api;
pub mod audit;
pub mod cgroup;
pub mod config;
pub mod confine;
pub mod host;
pub mod images;
pub mod input;
pub mod mcp;
pub mod mcp_http;
pub mod net;
pub mod paths;
pub mod qemu;
pub mod qga;
pub mod qmp;
pub mod run;
pub mod seed;
pub mod snapshot;
pub mod vm;

use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, bail};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt};
use tokio::process::Command;

/// Reads one `\n`-terminated line into `buf` (cleared first, newline
/// stripped). Returns `Ok(false)` on a clean end of stream.
///
/// Memory stays bounded: a line longer than `max` bytes is an error after at
/// most `max + 1` bytes are buffered. Every protocol reader in Stallo (QMP,
/// QGA, the API socket) goes through this.
pub async fn read_line<R: AsyncBufRead + Unpin>(
    r: &mut R,
    buf: &mut Vec<u8>,
    max: usize,
) -> std::io::Result<bool> {
    use std::io::{Error, ErrorKind};
    buf.clear();
    let n = (&mut *r)
        .take(max as u64 + 1)
        .read_until(b'\n', buf)
        .await?;
    if n == 0 {
        return Ok(false);
    }
    if buf.pop() != Some(b'\n') {
        return Err(if n > max {
            Error::new(
                ErrorKind::InvalidData,
                format!("line longer than {max} bytes"),
            )
        } else {
            Error::new(ErrorKind::UnexpectedEof, "stream ended mid-line")
        });
    }
    Ok(true)
}

/// Runs a helper program (fixed argv, never a shell) with a time limit and
/// returns its stdout. The child is killed if the limit passes or the
/// caller gives up. Errors carry the exit status and the last stderr line.
// ponytail: stdout and stderr are buffered whole; fine for the small outputs
// of curl, gpgv, qemu-img and xorriso. Stream them if a chatty tool appears.
pub async fn run_tool(cmd: &mut Command, limit: Duration) -> anyhow::Result<Vec<u8>> {
    cgroup::confine_tool(cmd)?;
    run_prepared(cmd, limit).await
}

/// [`run_tool`] for a command that already joins the tools cgroup (that
/// `pre_exec` hook must come before any confinement hook).
pub(crate) async fn run_prepared(cmd: &mut Command, limit: Duration) -> anyhow::Result<Vec<u8>> {
    let program = cmd.as_std().get_program().to_string_lossy().into_owned();
    cmd.stdin(Stdio::null()).kill_on_drop(true);
    let out = tokio::time::timeout(limit, cmd.output())
        .await
        .map_err(|_| anyhow::anyhow!("{program} timed out after {limit:?}"))?
        .with_context(|| format!("cannot run {program}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let last = stderr.lines().rev().find(|l| !l.trim().is_empty());
        bail!(
            "{program} failed ({}): {}",
            out.status,
            last.unwrap_or("no output")
        );
    }
    Ok(out.stdout)
}

/// Text from an untrusted peer (guest, QEMU), made safe to show: at most
/// `max` characters, without control characters or the Unicode format
/// characters that reorder or hide text (bidi overrides, zero-width).
pub fn printable(s: &str, max: usize) -> String {
    s.chars()
        .filter(|c| {
            !c.is_control()
                && !matches!(
                    c,
                    '\u{200B}'..='\u{200F}'
                        | '\u{202A}'..='\u{202E}'
                        | '\u{2066}'..='\u{2069}'
                        | '\u{FEFF}'
                )
        })
        .take(max)
        .collect()
}

/// `N` bytes from the kernel's CSPRNG.
pub fn random_bytes<const N: usize>() -> std::io::Result<[u8; N]> {
    use std::io::Read;
    let mut bytes = [0; N];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::read_line;

    #[tokio::test]
    async fn read_line_caps_and_strips() {
        let mut buf = Vec::new();
        let mut r: &[u8] = b"abc\ndefg\nxy";
        assert!(read_line(&mut r, &mut buf, 4).await.unwrap());
        assert_eq!(buf, b"abc");
        // "defg\n" is 5 bytes: the newline does not count against the cap.
        assert!(read_line(&mut r, &mut buf, 4).await.unwrap());
        assert_eq!(buf, b"defg");
        let err = read_line(&mut r, &mut buf, 4).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);

        let mut long: &[u8] = b"abcdef\n";
        let err = read_line(&mut long, &mut buf, 4).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(buf.len(), 4, "only max + 1 bytes were buffered");

        let mut empty: &[u8] = b"";
        assert!(!read_line(&mut empty, &mut buf, 4).await.unwrap());
    }

    #[test]
    fn printable_drops_control_and_bidi() {
        use super::printable;
        let s = "a\nb\u{1b}[0m\u{202E}c\u{200B}d";
        assert_eq!(printable(s, 200), "ab[0mcd");
        assert_eq!(printable(&"é".repeat(300), 200).chars().count(), 200);
    }

    #[tokio::test]
    async fn run_tool_reports_failures_and_timeouts() {
        use super::run_tool;
        use std::time::Duration;
        use tokio::process::Command;
        let t = Duration::from_secs(5);
        let out = run_tool(Command::new("echo").arg("hi"), t).await.unwrap();
        assert_eq!(out, b"hi\n");
        let err = run_tool(Command::new("sh").args(["-c", "echo bad >&2; exit 3"]), t)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("bad"), "{err:#}");
        let err = run_tool(Command::new("sleep").arg("5"), Duration::from_millis(50))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("timed out"), "{err:#}");
        assert!(
            run_tool(&mut Command::new("/nonexistent"), t)
                .await
                .is_err()
        );
    }
}
