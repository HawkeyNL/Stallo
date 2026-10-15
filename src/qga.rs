//! QEMU guest agent (QGA) client.
//!
//! QGA has no greeting and no request ids, and bytes from an earlier,
//! interrupted session can still be queued. So every connection starts with
//! `guest-sync-delimited`: the agent answers with `0xFF` followed by our
//! random id, and everything before that is discarded. After that, requests
//! and replies alternate one at a time.
//!
//! The guest is untrusted. Replies are parsed into typed structs (unknown
//! fields are skipped, not stored), so memory stays near the line cap.

use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::Deserialize;
use serde::de::{DeserializeOwned, IgnoredAny};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::time::{sleep, timeout};

use crate::read_line;

/// Longest reply line accepted. QGA caps each exec stream at 16 MiB, which is
/// about 22 MiB as base64, and a reply can carry stdout and stderr.
pub const MAX_LINE: usize = 48 << 20;

/// Largest stderr kept from a guest command.
const ERR_CAP: usize = 1 << 20;

/// A sync reply is tiny; anything longer is not ours.
const MAX_SYNC_LINE: usize = 256;

/// Longest reply to anything but `guest-exec-status`.
const SMALL_LINE: usize = 64 << 10;

/// Time allowed for one request/reply round trip.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(10);

/// `guest-exec-status` may carry tens of MiB over virtio-serial.
const STATUS_TIMEOUT: Duration = Duration::from_secs(60);

/// How long past its limit the daemon waits for a command that the guest
/// should already have killed.
const GRACE: Duration = if cfg!(test) {
    Duration::from_millis(300)
} else {
    Duration::from_secs(15)
};

pub struct Qga {
    r: BufReader<OwnedReadHalf>,
    w: OwnedWriteHalf,
    line: Vec<u8>,
}

/// Result of a finished guest command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOutput {
    /// The exit status, or 128 + signal number if a signal ended it.
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// Output beyond the cap (ours or the agent's) was dropped.
    pub truncated: bool,
}

#[derive(Deserialize)]
struct Reply<T> {
    #[serde(rename = "return")]
    ret: Option<T>,
    error: Option<ReplyError>,
}

#[derive(Deserialize)]
struct ReplyError {
    class: Option<String>,
    desc: Option<String>,
}

#[derive(Deserialize)]
struct Pid {
    pid: i64,
}

/// Base64 output is borrowed from the reply line; it never contains JSON
/// escapes, and a reply that does simply fails to parse.
#[derive(Deserialize)]
struct ExecStatus<'a> {
    exited: bool,
    exitcode: Option<i64>,
    signal: Option<i64>,
    #[serde(rename = "out-data", borrow)]
    out_data: Option<&'a str>,
    #[serde(rename = "err-data", borrow)]
    err_data: Option<&'a str>,
    #[serde(rename = "out-truncated", default)]
    out_truncated: bool,
    #[serde(rename = "err-truncated", default)]
    err_truncated: bool,
}

impl Qga {
    /// Connects and synchronises. Fails if the agent does not answer within
    /// `wait`, for example while the guest is still booting.
    pub async fn connect(path: &Path, wait: Duration) -> Result<Self> {
        timeout(wait, async {
            let (r, w) = UnixStream::connect(path).await?.into_split();
            let mut qga = Self {
                r: BufReader::new(r),
                w,
                line: Vec::new(),
            };
            qga.sync().await?;
            Ok::<_, anyhow::Error>(qga)
        })
        .await
        .map_err(|_| anyhow!("guest agent did not answer within {wait:?}"))?
        .context("guest agent")
    }

    /// Re-synchronises a connection kept from an earlier operation, so a
    /// guest agent that restarted (or stale bytes) is noticed.
    pub async fn resync(&mut self, wait: Duration) -> Result<()> {
        timeout(wait, self.sync())
            .await
            .map_err(|_| anyhow!("guest agent did not answer within {wait:?}"))?
    }

    async fn sync(&mut self) -> Result<()> {
        let id = u64::from_ne_bytes(crate::random_bytes()?) >> 11; // < 2^53
        // The leading 0xFF makes the agent drop any partial request it holds.
        let mut msg = vec![0xFF];
        msg.extend(serde_json::to_vec(
            &json!({"execute": "guest-sync-delimited", "arguments": {"id": id}}),
        )?);
        msg.push(b'\n');
        self.w.write_all(&msg).await?;
        loop {
            // Discard everything up to the agent's 0xFF marker without
            // buffering it (0xFF never occurs in UTF-8 JSON).
            loop {
                let buf = self.r.fill_buf().await?;
                if buf.is_empty() {
                    bail!("guest agent closed the connection while syncing");
                }
                match buf.iter().position(|&b| b == 0xFF) {
                    Some(i) => {
                        self.r.consume(i + 1);
                        break;
                    }
                    None => {
                        let n = buf.len();
                        self.r.consume(n);
                    }
                }
            }
            if !read_line(&mut self.r, &mut self.line, MAX_SYNC_LINE).await? {
                bail!("guest agent closed the connection");
            }
            // Stale replies from older syncs are skipped; ours carries `id`.
            if serde_json::from_slice::<Reply<u64>>(&self.line).is_ok_and(|r| r.ret == Some(id)) {
                return Ok(());
            }
        }
    }

    /// Sends one command and leaves its raw reply line in `self.line`.
    async fn request(
        &mut self,
        command: &str,
        arguments: Value,
        max: usize,
        wait: Duration,
    ) -> Result<()> {
        let mut msg = serde_json::to_vec(&json!({"execute": command, "arguments": arguments}))?;
        msg.push(b'\n');
        // A large earlier reply must not keep its buffer.
        if self.line.capacity() > 1 << 20 {
            self.line = Vec::new();
        }
        timeout(wait, async {
            self.w.write_all(&msg).await?;
            if !read_line(&mut self.r, &mut self.line, max).await? {
                bail!("guest agent closed the connection");
            }
            Ok(())
        })
        .await
        .map_err(|_| anyhow!("guest agent did not answer within {wait:?}"))?
        .with_context(|| format!("QGA {command}"))
    }

    /// Runs a command with a small reply and returns its typed `return`.
    async fn call<T: DeserializeOwned>(&mut self, command: &str, arguments: Value) -> Result<T> {
        self.request(command, arguments, SMALL_LINE, CALL_TIMEOUT)
            .await?;
        unwrap_reply(serde_json::from_slice(&self.line)?).with_context(|| format!("QGA {command}"))
    }

    /// The guest's IP addresses with their interface names, e.g.
    /// `("lo", "127.0.0.1/8")`. Guest data: only valid addresses, names cut
    /// to 15 bytes (IFNAMSIZ), at most 64 entries.
    pub async fn addresses(&mut self) -> Result<Vec<(String, String)>> {
        #[derive(Deserialize)]
        struct Iface {
            name: String,
            #[serde(rename = "ip-addresses", default)]
            ips: Vec<Ip>,
        }
        #[derive(Deserialize)]
        struct Ip {
            #[serde(rename = "ip-address")]
            addr: String,
            prefix: Option<u64>,
        }
        let ifaces: Vec<Iface> = self.call("guest-network-get-interfaces", json!({})).await?;
        Ok(ifaces
            .into_iter()
            .flat_map(|i| {
                let name: String = i
                    .name
                    .chars()
                    .filter(|c| c.is_ascii_graphic())
                    .take(15)
                    .collect();
                i.ips.into_iter().filter_map(move |ip| {
                    let addr: std::net::IpAddr = ip.addr.parse().ok()?;
                    let prefix = ip.prefix.filter(|&p| p <= 128)?;
                    Some((name.clone(), format!("{addr}/{prefix}")))
                })
            })
            .take(64)
            .collect())
    }

    pub async fn ping(&mut self) -> Result<()> {
        self.call::<IgnoredAny>("guest-ping", json!({}))
            .await
            .map(drop)
    }

    /// Runs `path args...` in the guest, with `stdin` as its input, and
    /// waits for it to exit. The caller makes the guest enforce `limit` (QGA
    /// itself cannot kill a command); here `limit` plus a grace period is
    /// only a backstop. stdout is cut at `cap` bytes, stderr at
    /// `min(cap, 1 MiB)`.
    pub async fn exec(
        &mut self,
        path: &str,
        args: &[String],
        stdin: Option<&[u8]>,
        limit: Duration,
        cap: usize,
    ) -> Result<ExecOutput> {
        let started = Instant::now();
        let mut arguments = json!({"path": path, "arg": args, "capture-output": true});
        if let Some(input) = stdin {
            arguments["input-data"] = BASE64.encode(input).into();
        }
        let pid = self.call::<Pid>("guest-exec", arguments).await?.pid;
        // Short commands finish within ~100 ms (most of it the guest's
        // systemd-run scope), so poll often at first, then back off: polls
        // cost one small round trip each.
        let mut delay = Duration::from_millis(5);
        loop {
            // Output can be large: two 16 MiB streams as base64.
            self.request(
                "guest-exec-status",
                json!({"pid": pid}),
                MAX_LINE,
                STATUS_TIMEOUT,
            )
            .await?;
            // Borrowed from the line: the output is not copied again.
            let status: ExecStatus = unwrap_reply(serde_json::from_slice(&self.line)?)
                .context("QGA guest-exec-status")?;
            if status.exited {
                let out = parse_status(status, cap);
                // A kept connection must not hold a large reply's buffer.
                if self.line.capacity() > 1 << 20 {
                    self.line = Vec::new();
                }
                return out;
            }
            if started.elapsed() >= limit + GRACE {
                bail!("command did not finish within {limit:?} and the guest did not stop it");
            }
            sleep(delay).await;
            delay = (delay * 3 / 2).min(Duration::from_millis(500));
        }
    }
}

fn unwrap_reply<T>(reply: Reply<T>) -> Result<T> {
    match (reply.ret, reply.error) {
        (Some(v), _) => Ok(v),
        (None, Some(e)) => bail!(
            "{}: {}",
            e.class.as_deref().unwrap_or("Error"),
            e.desc.as_deref().unwrap_or("unknown error")
        ),
        (None, None) => bail!("malformed reply"),
    }
}

fn parse_status(status: ExecStatus, cap: usize) -> Result<ExecOutput> {
    let exit_code = match (status.exitcode, status.signal) {
        (Some(code), _) => code as i32,
        (None, Some(sig)) => 128 + sig as i32,
        (None, None) => bail!("guest-exec-status has neither exitcode nor signal"),
    };
    let (stdout, cut_out) = decode_capped(status.out_data, cap)?;
    // stderr is for messages: never more than the exec cap.
    let (stderr, cut_err) = decode_capped(status.err_data, cap.min(ERR_CAP))?;
    Ok(ExecOutput {
        exit_code,
        stdout,
        stderr,
        truncated: cut_out || cut_err || status.out_truncated || status.err_truncated,
    })
}

/// Decodes at most `cap` bytes of base64 without decoding the rest.
fn decode_capped(text: Option<&str>, cap: usize) -> Result<(Vec<u8>, bool)> {
    let Some(text) = text else {
        return Ok((Vec::new(), false));
    };
    // 4 base64 characters carry 3 bytes; decode whole groups only.
    let chars = cap.div_ceil(3) * 4;
    let cut = text.len() > chars;
    let mut bytes = BASE64
        .decode(&text.as_bytes()[..text.len().min(chars)])
        .context("guest sent invalid base64")?;
    let cut = cut || bytes.len() > cap;
    bytes.truncate(cap);
    Ok((bytes, cut))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UnixListener;

    /// A fake guest agent. `reply` maps each request (after sync) to the
    /// bytes to send back; `None` closes the connection.
    async fn fake<F>(stale: &'static [u8], mut reply: F) -> (tempfile::TempDir, std::path::PathBuf)
    where
        F: FnMut(&Value) -> Option<Vec<u8>> + Send + 'static,
    {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("qga.sock");
        let listener = UnixListener::bind(&path).unwrap();
        tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            let (r, mut w) = s.into_split();
            let mut r = BufReader::new(r);
            let mut line = Vec::new();
            loop {
                line.clear();
                if r.read_until(b'\n', &mut line).await.unwrap() == 0 {
                    return;
                }
                let text = line.strip_prefix(&[0xFF]).unwrap_or(&line);
                let req: Value = serde_json::from_slice(text).unwrap();
                let out = if req["execute"] == "guest-sync-delimited" {
                    let id = &req["arguments"]["id"];
                    let mut out = stale.to_vec();
                    out.extend(b"\xff{\"return\": 1}\n\xff");
                    out.extend(format!("{{\"return\": {id}}}\n").as_bytes());
                    Some(out)
                } else {
                    reply(&req)
                };
                match out {
                    Some(bytes) => {
                        if w.write_all(&bytes).await.is_err() {
                            return;
                        }
                    }
                    None => return,
                }
            }
        });
        (dir, path)
    }

    const WAIT: Duration = Duration::from_secs(5);

    #[tokio::test]
    async fn lists_addresses() {
        let (_d, path) = fake(b"", |_| {
            Some(
                json!({"return": [
                    {"name": "lo", "ip-addresses": [
                        {"ip-address": "127.0.0.1", "ip-address-type": "ipv4", "prefix": 8},
                        {"ip-address": "::1", "ip-address-type": "ipv6", "prefix": 128}]},
                    {"name": "eth0"},
                    {"name": "evil\u{1b}[2Jname-that-is-far-too-long", "ip-addresses": [
                        {"ip-address": "not an ip", "prefix": 8},
                        {"ip-address": "10.0.0.2", "prefix": 300},
                        {"ip-address": "10.0.0.3", "prefix": 24}]}
                ]})
                .to_string()
                .into_bytes()
                .into_iter()
                .chain(*b"\n")
                .collect(),
            )
        })
        .await;
        let mut qga = Qga::connect(&path, WAIT).await.unwrap();
        assert_eq!(
            qga.addresses().await.unwrap(),
            [
                ("lo".to_owned(), "127.0.0.1/8".to_owned()),
                ("lo".to_owned(), "::1/128".to_owned()),
                ("evil[2Jname-tha".to_owned(), "10.0.0.3/24".to_owned())
            ]
        );
    }

    #[tokio::test]
    async fn sync_skips_stale_bytes_then_pings() {
        let stale: &[u8] = b"{\"return\": {\"pid\": 1}}\ngarbage";
        let (_d, path) = fake(stale, |req| {
            assert_eq!(req["execute"], "guest-ping");
            Some(b"{\"return\": {}}\n".to_vec())
        })
        .await;
        let mut qga = Qga::connect(&path, WAIT).await.unwrap();
        qga.ping().await.unwrap();
        // A kept connection syncs again before the next use.
        qga.resync(WAIT).await.unwrap();
        qga.ping().await.unwrap();
    }

    #[tokio::test]
    async fn resync_skips_a_late_reply() {
        // After the first ping, the agent sends a late reply and junk
        // before anything else: a kept connection must skip them.
        let mut first = true;
        let (_d, path) = fake(b"", move |_| {
            let mut out = b"{\"return\": {}}\n".to_vec();
            if std::mem::take(&mut first) {
                out.extend(b"{\"return\": {\"pid\": 1}}\njunk");
            }
            Some(out)
        })
        .await;
        let mut qga = Qga::connect(&path, WAIT).await.unwrap();
        qga.ping().await.unwrap();
        qga.resync(WAIT).await.unwrap();
        qga.ping().await.unwrap();
    }

    #[tokio::test]
    async fn exec_polls_until_exit_and_caps_output() {
        let mut polls = 0;
        let (_d, path) = fake(b"", move |req| {
            let reply = match req["execute"].as_str().unwrap() {
                "guest-exec" => {
                    assert_eq!(req["arguments"]["path"], "uname");
                    assert_eq!(req["arguments"]["arg"], json!(["-a"]));
                    assert_eq!(req["arguments"]["input-data"], BASE64.encode(b"in"));
                    json!({"return": {"pid": 42}})
                }
                "guest-exec-status" if polls == 0 => {
                    polls += 1;
                    json!({"return": {"exited": false}})
                }
                "guest-exec-status" => json!({"return": {
                    "exited": true, "exitcode": 3,
                    "out-data": BASE64.encode(b"hello world"),
                    "err-data": BASE64.encode(b"oops"),
                }}),
                other => panic!("unexpected {other}"),
            };
            Some(format!("{reply}\n").into_bytes())
        })
        .await;
        let mut qga = Qga::connect(&path, WAIT).await.unwrap();
        let out = qga
            .exec("uname", &["-a".to_owned()], Some(b"in"), WAIT, 5)
            .await
            .unwrap();
        assert_eq!(out.exit_code, 3);
        assert_eq!(out.stdout, b"hello");
        assert_eq!(out.stderr, b"oops");
        assert!(out.truncated);
    }

    #[test]
    fn status_parsing() {
        let parse = |v: Value| {
            let text = v.to_string();
            parse_status(serde_json::from_str::<ExecStatus>(&text).unwrap(), 10)
        };
        assert_eq!(
            parse(json!({"exited": true, "signal": 9}))
                .unwrap()
                .exit_code,
            137
        );
        assert!(parse(json!({"exited": true, "exitcode": 0, "out-data": "!!notbase64"})).is_err());
        let r = parse(json!({"exited": true, "exitcode": 0, "out-truncated": true}));
        assert!(r.unwrap().truncated);
        let big = BASE64.encode(vec![7u8; 3 << 20]);
        let (bytes, cut) = decode_capped(Some(&big), 1 << 20).unwrap();
        assert_eq!(bytes.len(), 1 << 20);
        assert!(cut);
        let (bytes, cut) = decode_capped(Some(&BASE64.encode(b"abc")), 3).unwrap();
        assert_eq!((bytes.as_slice(), cut), (&b"abc"[..], false));
    }

    #[tokio::test]
    async fn backstop_when_the_guest_never_finishes() {
        let (_d, path) = fake(b"", move |req| {
            let reply = match req["execute"].as_str().unwrap() {
                "guest-exec" => json!({"return": {"pid": 7}}),
                _ => json!({"return": {"exited": false}}),
            };
            Some(format!("{reply}\n").into_bytes())
        })
        .await;
        let mut qga = Qga::connect(&path, WAIT).await.unwrap();
        let err = qga
            .exec("sleep", &["9".to_owned()], None, Duration::from_secs(1), 10)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("did not stop"), "{err:#}");
    }

    #[tokio::test]
    async fn sync_survives_much_garbage_and_fails_on_endless_wrong_ids() {
        // 64 MiB of junk before the marker is streamed away, not buffered.
        let junk: &'static [u8] = Box::leak(vec![b'j'; 64 << 20].into_boxed_slice());
        let (_d, path) = fake(junk, |_| Some(b"{\"return\": {}}\n".to_vec())).await;
        Qga::connect(&path, Duration::from_secs(20))
            .await
            .unwrap()
            .ping()
            .await
            .unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("qga.sock");
        let listener = UnixListener::bind(&path).unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            while s.write_all(b"\xff{\"return\": 1}\n").await.is_ok() {}
        });
        let err = Qga::connect(&path, Duration::from_millis(200))
            .await
            .err()
            .unwrap();
        assert!(err.to_string().contains("did not answer"), "{err:#}");
    }

    #[tokio::test]
    async fn error_replies_and_oversized_lines_fail() {
        let mut n = 0;
        let (_d, path) = fake(b"", move |_| {
            n += 1;
            if n == 1 {
                return Some(
                    b"{\"error\": {\"class\": \"GenericError\", \"desc\": \"no\"}}\n".to_vec(),
                );
            }
            // 100 MiB without a newline.
            Some(vec![b'x'; 100 << 20])
        })
        .await;
        let mut qga = Qga::connect(&path, WAIT).await.unwrap();
        let err = qga.ping().await.unwrap_err();
        assert!(format!("{err:#}").contains("GenericError: no"), "{err:#}");
        let err = qga.ping().await.unwrap_err();
        assert!(format!("{err:#}").contains("longer than"), "{err:#}");
    }

    #[tokio::test]
    async fn silent_agent_times_out() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("qga.sock");
        let listener = UnixListener::bind(&path).unwrap();
        tokio::spawn(async move {
            let (_s, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        });
        let err = Qga::connect(&path, Duration::from_millis(100))
            .await
            .err()
            .unwrap();
        assert!(err.to_string().contains("did not answer"), "{err:#}");
    }
}
