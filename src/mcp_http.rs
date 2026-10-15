//! `stallo mcp --http <addr>:<port>`: the MCP tools over streamable HTTP,
//! for an agent on another machine of the owner's tailnet.
//!
//! The same thin client as stdio (`mcp.rs`, every call `via: mcp`), behind
//! checks that run before any request body is read:
//!
//! - the address must be loopback or Tailscale (`100.64.0.0/10`,
//!   `fd7a:115c:a1e0::/48`); never a wildcard or a LAN address. Peers must
//!   come from the same class of address (Linux would also deliver LAN
//!   packets addressed to the Tailscale IP);
//! - at most [`MAX_CONNECTIONS`] connections, [`MAX_PER_PEER`] per peer;
//! - a bearer token from a private file, compared in constant time;
//! - at most [`RATE`] authenticated requests per second, and a separate,
//!   smaller budget for failed ones, so junk cannot starve the agent.
//!
//! There is no TLS: on loopback nothing leaves the host, and Tailscale
//! encrypts. The daemon itself still listens on no IP socket (S1); this
//! runs as the user who starts it, with the API access of that user.

use std::collections::HashMap;
use std::convert::Infallible;
use std::fs;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::{AUTHORIZATION, HeaderMap, WWW_AUTHENTICATE};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use rmcp::transport::streamable_http_server::session::never::NeverSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tower_service::Service;

use crate::mcp::{MAX_MESSAGE, Server};

/// Authenticated requests per second, and the burst allowed.
pub const RATE: u32 = 20;
/// Requests with a missing or wrong token per second (all peers together).
const FAILED_RATE: u32 = 5;
/// TCP connections served at once.
const MAX_CONNECTIONS: usize = 8;
/// TCP connections from one peer address at once.
const MAX_PER_PEER: usize = 4;
/// A client must send its request headers within this time (also between
/// requests on a kept-alive connection).
const HEADER_TIMEOUT: Duration = Duration::from_secs(3);
/// Shortest token accepted (bytes, after trimming).
const MIN_TOKEN: usize = 32;

/// The address classes `--http` may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    Loopback,
    Tailscale,
}

/// Loopback, Tailscale, or neither (also every IPv4-mapped IPv6 address).
fn class(ip: IpAddr) -> Option<Class> {
    match ip {
        IpAddr::V4(v4) if v4.is_loopback() => Some(Class::Loopback),
        IpAddr::V4(v4) if in_v4(v4, Ipv4Addr::new(100, 64, 0, 0), 10) => Some(Class::Tailscale),
        IpAddr::V6(v6) if v6.is_loopback() => Some(Class::Loopback),
        IpAddr::V6(v6) if in_v6(v6, Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0), 48) => {
            Some(Class::Tailscale)
        }
        _ => None,
    }
}

/// Refuses every address but loopback and Tailscale's ranges.
pub fn check_addr(addr: SocketAddr) -> Result<()> {
    ensure!(addr.port() != 0, "pick a port for --http");
    ensure!(
        class(addr.ip()).is_some(),
        "refusing to listen on {}: only loopback (127.0.0.1, ::1) or a Tailscale address (100.64.0.0/10, fd7a:115c:a1e0::/48)",
        addr.ip()
    );
    Ok(())
}

fn in_v4(ip: Ipv4Addr, net: Ipv4Addr, bits: u32) -> bool {
    let mask = u32::MAX << (32 - bits);
    u32::from(ip) & mask == u32::from(net) & mask
}

fn in_v6(ip: Ipv6Addr, net: Ipv6Addr, bits: u32) -> bool {
    let mask = u128::MAX << (128 - bits);
    u128::from(ip) & mask == u128::from(net) & mask
}

/// The token's SHA-256: comparing digests takes the same time for every
/// guess, whatever its length.
struct Token([u8; 32]);

impl Token {
    /// Reads the token from `path`: a regular file of this user that nobody
    /// else can read or write (not a symlink), at least [`MIN_TOKEN`] bytes.
    fn load(path: &Path) -> Result<Self> {
        // O_NONBLOCK: a FIFO must not hang the open before the checks.
        let mut file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .with_context(|| format!("cannot open the token file {}", path.display()))?;
        let meta = file.metadata()?;
        ensure!(meta.is_file(), "{} is not a regular file", path.display());
        ensure!(
            meta.uid() == rustix::process::geteuid().as_raw(),
            "{} belongs to another user",
            path.display()
        );
        ensure!(
            meta.mode() & 0o077 == 0,
            "{} is readable or writable by others; chmod 600 it",
            path.display()
        );
        let mut text = String::new();
        file.by_ref().take(4096).read_to_string(&mut text)?;
        let token = text.trim();
        // Visible ASCII only: anything else could never pass an HTTP header.
        ensure!(
            token.len() >= MIN_TOKEN && token.bytes().all(|b| b.is_ascii_graphic()),
            "the token in {} must be one word of at least {MIN_TOKEN} printable ASCII characters",
            path.display()
        );
        Ok(Self(Sha256::digest(token).into()))
    }

    fn matches(&self, given: &str) -> bool {
        let given: [u8; 32] = Sha256::digest(given).into();
        given.iter().zip(&self.0).fold(0, |d, (a, b)| d | (a ^ b)) == 0
    }
}

/// A token bucket: `rate` requests per second, bursts up to `rate`.
struct Bucket {
    rate: f64,
    tokens: f64,
    last: Instant,
}

impl Bucket {
    fn new(rate: u32, now: Instant) -> Self {
        Self {
            rate: f64::from(rate),
            tokens: f64::from(rate),
            last: now,
        }
    }

    fn allow(&mut self, now: Instant) -> bool {
        let refill = now.saturating_duration_since(self.last).as_secs_f64() * self.rate;
        self.tokens = (self.tokens + refill).min(self.rate);
        self.last = now;
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}

/// The checks every request passes before it reaches MCP.
struct Gate {
    token: Token,
    ok: Mutex<Bucket>,
    failed: Mutex<Bucket>,
}

impl Gate {
    fn new(token: Token, now: Instant) -> Self {
        Self {
            token,
            ok: Mutex::new(Bucket::new(RATE, now)),
            failed: Mutex::new(Bucket::new(FAILED_RATE, now)),
        }
    }

    /// `None` lets the request through; otherwise the refusal. A failed
    /// request only spends the failure budget.
    fn check(&self, headers: &HeaderMap, now: Instant) -> Option<StatusCode> {
        let given = headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split_once(' '))
            .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
            .map(|(_, token)| token);
        let (bucket, refusal) = match given {
            Some(t) if self.token.matches(t) => (&self.ok, None),
            _ => (&self.failed, Some(StatusCode::UNAUTHORIZED)),
        };
        if !bucket.lock().unwrap().allow(now) {
            return Some(StatusCode::TOO_MANY_REQUESTS);
        }
        refusal
    }
}

/// Connections per peer address; a slot is given back when dropped.
#[derive(Default)]
struct Peers(Mutex<HashMap<IpAddr, usize>>);

struct PeerSlot(Arc<Peers>, IpAddr);

impl Peers {
    fn take(self: &Arc<Self>, ip: IpAddr) -> Option<PeerSlot> {
        let mut map = self.0.lock().unwrap();
        let n = map.entry(ip).or_default();
        if *n >= MAX_PER_PEER {
            return None;
        }
        *n += 1;
        Some(PeerSlot(self.clone(), ip))
    }
}

impl Drop for PeerSlot {
    fn drop(&mut self) {
        let mut map = (self.0).0.lock().unwrap();
        if let Some(n) = map.get_mut(&self.1) {
            *n -= 1;
            if *n == 0 {
                map.remove(&self.1);
            }
        }
    }
}

fn refusal(
    status: StatusCode,
) -> Response<http_body_util::combinators::BoxBody<Bytes, Infallible>> {
    let mut r = Response::new(Full::new(Bytes::from(status.as_str().to_owned())).boxed());
    *r.status_mut() = status;
    // Free the connection slot at once.
    r.headers_mut().insert(
        hyper::header::CONNECTION,
        hyper::header::HeaderValue::from_static("close"),
    );
    if status == StatusCode::UNAUTHORIZED {
        r.headers_mut().insert(
            WWW_AUTHENTICATE,
            hyper::header::HeaderValue::from_static("Bearer"),
        );
    }
    r
}

/// Serves MCP over HTTP on `addr` until the process is stopped.
pub async fn serve(socket: PathBuf, addr: SocketAddr, token_file: &Path) -> Result<()> {
    check_addr(addr)?;
    let gate = Arc::new(Gate::new(Token::load(token_file)?, Instant::now()));
    // Stateless: no session table for anyone to fill; every request gets a
    // clone of one server, so the daemon-request limit is shared.
    // Origin: agents send none; a browser always does, and is refused.
    let mut config = StreamableHttpServerConfig::default().enforce_origin_validation();
    config.legacy_session_mode = false;
    config.json_response = true;
    config.max_request_body_bytes = MAX_MESSAGE;
    config.allowed_hosts = vec![addr.ip().to_string(), addr.to_string()];
    if addr.ip().is_loopback() {
        config.allowed_hosts.push("localhost".into());
        config
            .allowed_hosts
            .push(format!("localhost:{}", addr.port()));
    }
    let server = Server::new(socket);
    let mcp = StreamableHttpService::new(
        move || Ok(server.clone()),
        Arc::new(NeverSessionManager::default()),
        config,
    );
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("cannot listen on {addr}"))?;
    eprintln!("stallo mcp: listening on http://{addr}/ (bearer token required)");
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let peers = Arc::new(Peers::default());
    let want = class(addr.ip()).context("unreachable: checked above")?;
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(a) => a,
            Err(e) => {
                eprintln!("stallo mcp: accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        // A Tailscale listener also gets packets sent to its address over
        // the LAN (weak host model): only peers of the same class count.
        if class(peer.ip()) != Some(want) {
            eprintln!("stallo mcp: {peer}: refused (not a {want:?} address)");
            continue;
        }
        let Some(peer_slot) = peers.take(peer.ip()) else {
            eprintln!("stallo mcp: {peer}: refused (too many connections)");
            continue;
        };
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            eprintln!("stallo mcp: {peer}: refused (busy)");
            continue;
        };
        let (gate, mcp) = (gate.clone(), mcp.clone());
        let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
            let (gate, mut mcp) = (gate.clone(), mcp.clone());
            async move {
                let method = req.method().clone();
                let response = match gate.check(req.headers(), Instant::now()) {
                    Some(status) => refusal(status),
                    None => mcp.call(req).await?,
                };
                // Never the token or the body.
                eprintln!("stallo mcp: {peer} {method} {}", response.status().as_u16());
                Ok::<_, Infallible>(response)
            }
        });
        tokio::spawn(async move {
            let _ = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(HEADER_TIMEOUT)
                .serve_connection(TokioIo::new(stream), svc)
                .await;
            drop((permit, peer_slot));
        });
    }
}

/// `host:port` for `--http`; a bare IPv6 address needs brackets.
pub fn parse_addr(s: &str) -> Result<SocketAddr> {
    match s.parse() {
        Ok(a) => Ok(a),
        Err(_) => bail!("--http wants IP:PORT, e.g. 127.0.0.1:8765 or [::1]:8765"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn only_loopback_and_tailscale() {
        for ok in [
            "127.0.0.1:8765",
            "127.1.2.3:8765",
            "[::1]:8765",
            "100.64.0.1:8765",
            "100.127.255.254:8765",
            "[fd7a:115c:a1e0::1]:8765",
        ] {
            assert!(check_addr(ok.parse().unwrap()).is_ok(), "{ok}");
        }
        for bad in [
            "0.0.0.0:8765",
            "[::]:8765",
            "192.168.1.10:8765",
            "10.0.0.1:8765",
            "100.128.0.1:8765",
            "100.63.255.255:8765",
            "8.8.8.8:8765",
            "[fd7a:115c:a1e1::1]:8765",
            "[fe80::1]:8765",
            "[::ffff:192.168.1.1]:8765",
            "[::ffff:0.0.0.0]:8765",
            "[::ffff:127.0.0.1]:8765",
            "[::ffff:100.64.0.1]:8765",
            "127.0.0.1:0",
        ] {
            assert!(check_addr(bad.parse().unwrap()).is_err(), "{bad}");
        }
        assert!(parse_addr("localhost:8765").is_err());
    }

    fn token_file(dir: &Path, text: &str, mode: u32) -> PathBuf {
        let p = dir.join(format!("token-{mode:o}-{}", text.len()));
        fs::write(&p, text).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
        p
    }

    #[test]
    fn token_file_rules() {
        let tmp = tempfile::tempdir().unwrap();
        let good = "a".repeat(32);
        let t = Token::load(&token_file(tmp.path(), &format!("{good}\n"), 0o600)).unwrap();
        assert!(t.matches(&good));
        assert!(!t.matches(&"a".repeat(31)));
        assert!(!t.matches(""));
        assert!(Token::load(&token_file(tmp.path(), &good, 0o400)).is_ok());
        for mode in [0o640, 0o604, 0o660] {
            assert!(
                Token::load(&token_file(tmp.path(), &good, mode)).is_err(),
                "{mode:o}"
            );
        }
        assert!(Token::load(&token_file(tmp.path(), "short", 0o600)).is_err());
        assert!(Token::load(&token_file(tmp.path(), &format!("{good} x"), 0o600)).is_err());
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(token_file(tmp.path(), &good, 0o600), &link).unwrap();
        assert!(Token::load(&link).is_err());
        assert!(Token::load(tmp.path()).is_err());
    }

    #[test]
    fn gate_budgets() {
        let now = Instant::now();
        let secret = "s".repeat(40);
        let gate = Gate::new(Token(Sha256::digest(&secret).into()), now);
        let headers = |v: &str| {
            let mut h = HeaderMap::new();
            h.insert(AUTHORIZATION, v.parse().unwrap());
            h
        };
        let good = headers(&format!("Bearer {secret}"));
        let bad = headers(&format!("Bearer {secret}x"));
        // The scheme is case-insensitive (RFC 7235).
        assert_eq!(gate.check(&headers(&format!("bearer {secret}")), now), None);
        assert_eq!(gate.check(&good, now), None);
        assert_eq!(
            gate.check(&HeaderMap::new(), now),
            Some(StatusCode::UNAUTHORIZED)
        );
        assert_eq!(
            gate.check(&headers(&format!("Basic {secret}")), now),
            Some(StatusCode::UNAUTHORIZED)
        );
        // Failures have their own small budget: 2 used, 3 left, then 429.
        for _ in 2..FAILED_RATE {
            assert_eq!(gate.check(&bad, now), Some(StatusCode::UNAUTHORIZED));
        }
        assert_eq!(gate.check(&bad, now), Some(StatusCode::TOO_MANY_REQUESTS));
        // ... which does not touch the agent's: 2 used, 18 left.
        for _ in 2..RATE {
            assert_eq!(gate.check(&good, now), None);
        }
        assert_eq!(gate.check(&good, now), Some(StatusCode::TOO_MANY_REQUESTS));
        let later = now + Duration::from_millis(100);
        assert_eq!(gate.check(&good, later), None);
        assert_eq!(gate.check(&good, later), None);
        assert_eq!(
            gate.check(&good, later),
            Some(StatusCode::TOO_MANY_REQUESTS)
        );
    }

    #[test]
    fn peer_classes_and_slots() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(class(ip("127.0.0.1")), Some(Class::Loopback));
        assert_eq!(class(ip("100.100.1.2")), Some(Class::Tailscale));
        assert_eq!(class(ip("192.168.1.2")), None);
        assert_eq!(class(ip("::ffff:100.100.1.2")), None);
        let peers = Arc::new(Peers::default());
        let held: Vec<_> = (0..MAX_PER_PEER)
            .map(|_| peers.take(ip("100.100.1.2")).unwrap())
            .collect();
        assert!(peers.take(ip("100.100.1.2")).is_none());
        assert!(peers.take(ip("100.100.1.3")).is_some());
        drop(held);
        assert!(peers.take(ip("100.100.1.2")).is_some());
        assert!(peers.0.lock().unwrap().is_empty());
    }
}
