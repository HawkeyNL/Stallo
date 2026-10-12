//! Stallo: an agent-first VM manager for Ubuntu on QEMU/KVM.
//!
//! `stallod` (the daemon) owns every VM; `stallo` (the CLI) talks to it over
//! a Unix socket.

pub mod config;
pub mod paths;
pub mod qmp;

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt};

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
}
