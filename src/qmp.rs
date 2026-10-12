//! Async QMP client: greeting, capability negotiation, id-matched commands
//! and an event broadcast.
//!
//! One background task reads the socket. Replies are routed to the waiting
//! caller by `id`; events go to every subscriber. QEMU is treated as an
//! untrusted peer: a line longer than [`MAX_LINE`] or invalid JSON stops the
//! reader, which fails every waiting and future command and ends every event
//! subscription.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{broadcast, oneshot};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::read_line;

/// Longest QMP line accepted from QEMU. Replies Stallo asks for are small.
pub const MAX_LINE: usize = 1 << 20;

/// Events with a longer line are dropped instead of being queued.
const MAX_EVENT_LINE: usize = 64 << 10;

/// Default time to wait for a command reply.
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

/// An asynchronous QMP event, such as `SHUTDOWN` or `JOB_STATUS_CHANGE`.
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    pub event: String,
    pub data: Value,
    /// When QEMU emitted it, in microseconds of QEMU's wall clock (0 if
    /// missing). Events are queued while QEMU's main loop is busy (for
    /// example during a snapshot), so the arrival time can be much later.
    pub micros: u64,
}

type Reply = std::result::Result<Value, String>;
/// `None` once the connection is closed.
type Pending = Arc<Mutex<Option<HashMap<u64, oneshot::Sender<Reply>>>>>;

pub struct Qmp {
    /// `None` once a write did not complete: a half-written command must
    /// never be glued to the next one.
    writer: tokio::sync::Mutex<Option<OwnedWriteHalf>>,
    pending: Pending,
    next_id: AtomicU64,
    /// Only the reader task holds the sender, so subscribers see `Closed`
    /// when it stops.
    events: broadcast::Receiver<Event>,
    reader: JoinHandle<()>,
}

impl Drop for Qmp {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

/// Removes a pending id however `execute` ends, including when its future
/// is dropped.
struct PendingGuard<'a> {
    pending: &'a Pending,
    id: u64,
}

impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        if let Some(map) = self.pending.lock().unwrap().as_mut() {
            map.remove(&self.id);
        }
    }
}

impl Qmp {
    /// Connects, reads the greeting and leaves negotiation mode.
    pub async fn connect(path: &Path, wait: Duration) -> Result<Self> {
        timeout(wait, Self::handshake(path))
            .await
            .map_err(|_| anyhow!("QMP handshake timed out"))?
            .with_context(|| format!("QMP connect to {}", path.display()))
    }

    async fn handshake(path: &Path) -> Result<Self> {
        let (r, mut w) = UnixStream::connect(path).await?.into_split();
        let mut r = BufReader::new(r);
        let mut line = Vec::new();

        let greeting = read_json(&mut r, &mut line).await?;
        if greeting.get("QMP").is_none() {
            bail!("unexpected QMP greeting");
        }
        w.write_all(b"{\"execute\":\"qmp_capabilities\"}\n").await?;
        // No events are sent before negotiation completes.
        let reply = read_json(&mut r, &mut line).await?;
        if reply.get("return").is_none() {
            bail!("qmp_capabilities failed: {reply}");
        }

        let pending: Pending = Arc::new(Mutex::new(Some(HashMap::new())));
        let (tx, events) = broadcast::channel(16);
        let reader = tokio::spawn(read_loop(r, pending.clone(), tx));
        Ok(Self {
            writer: tokio::sync::Mutex::new(Some(w)),
            pending,
            next_id: AtomicU64::new(1),
            events,
            reader,
        })
    }

    /// Subscribes to events. Only events read after this call are seen.
    /// `recv` returns `Closed` once the connection is gone.
    pub fn events(&self) -> broadcast::Receiver<Event> {
        self.events.resubscribe()
    }

    /// Runs `command` and returns its `return` value. Waits at most
    /// [`COMMAND_TIMEOUT`].
    pub async fn execute(&self, command: &str, arguments: Option<Value>) -> Result<Value> {
        self.execute_timeout(command, arguments, COMMAND_TIMEOUT)
            .await
    }

    pub async fn execute_timeout(
        &self,
        command: &str,
        arguments: Option<Value>,
        wait: Duration,
    ) -> Result<Value> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        match self.pending.lock().unwrap().as_mut() {
            Some(map) => map.insert(id, tx),
            None => bail!("QMP connection is closed"),
        };
        let _guard = PendingGuard {
            pending: &self.pending,
            id,
        };
        let mut msg = json!({ "execute": command, "id": id });
        if let Some(args) = arguments {
            msg["arguments"] = args;
        }
        let mut bytes = serde_json::to_vec(&msg)?;
        bytes.push(b'\n');

        let result = timeout(wait, async {
            {
                let mut slot = self.writer.lock().await;
                // Taken out while writing: if this future is dropped or the
                // write fails, the writer stays `None` (poisoned).
                let mut w = slot.take().context("QMP connection is broken")?;
                w.write_all(&bytes).await?;
                *slot = Some(w);
            }
            rx.await.map_err(|_| anyhow!("QMP connection closed"))
        })
        .await;
        match result {
            Ok(Ok(Ok(value))) => Ok(value),
            Ok(Ok(Err(desc))) => bail!("QMP {command}: {desc}"),
            Ok(Err(e)) => Err(e.context(format!("QMP {command}"))),
            Err(_) => bail!("QMP {command} timed out after {wait:?}"),
        }
    }
}

async fn read_json(r: &mut BufReader<OwnedReadHalf>, line: &mut Vec<u8>) -> Result<Value> {
    if !read_line(r, line, MAX_LINE).await? {
        bail!("QMP connection closed");
    }
    Ok(serde_json::from_slice(line)?)
}

async fn read_loop(
    mut r: BufReader<OwnedReadHalf>,
    pending: Pending,
    events: broadcast::Sender<Event>,
) {
    let mut line = Vec::new();
    loop {
        let mut msg = match read_json(&mut r, &mut line).await {
            Ok(msg) => msg,
            Err(e) => {
                tracing::debug!("QMP reader stops: {e:#}");
                break;
            }
        };
        let line_len = line.len();
        // Do not keep a large buffer around for the life of the VM.
        if line.capacity() > MAX_EVENT_LINE {
            line = Vec::new();
        }
        if let Some(name) = msg.get("event").and_then(Value::as_str) {
            if line_len > MAX_EVENT_LINE {
                tracing::warn!("oversized QMP event {name} dropped");
                continue;
            }
            // An error only means nobody is subscribed right now.
            let t = &msg["timestamp"];
            let micros = t["seconds"]
                .as_u64()
                .unwrap_or(0)
                .saturating_mul(1_000_000)
                .saturating_add(t["microseconds"].as_u64().unwrap_or(0).min(999_999));
            let _ = events.send(Event {
                event: name.to_owned(),
                data: msg["data"].take(),
                micros,
            });
            continue;
        }
        let Some(id) = msg.get("id").and_then(Value::as_u64) else {
            tracing::warn!("QMP message without id ignored");
            continue;
        };
        let reply = if msg.get("return").is_some() {
            Ok(msg["return"].take())
        } else if let Some(e) = msg.get("error") {
            Err(format!(
                "{}: {}",
                e["class"].as_str().unwrap_or("Error"),
                e["desc"].as_str().unwrap_or("unknown error")
            ))
        } else {
            Err("malformed reply".to_owned())
        };
        let waiter = pending.lock().unwrap().as_mut().and_then(|m| m.remove(&id));
        if let Some(tx) = waiter {
            let _ = tx.send(reply);
        }
    }
    // Dropping the senders wakes every waiter with "connection closed";
    // dropping `events` ends every subscription.
    pending.lock().unwrap().take();
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;

    const GREETING: &str = r#"{"QMP": {"version": {}, "capabilities": []}}"#;

    /// Starts a fake QEMU that greets, accepts `qmp_capabilities` and then
    /// hands the connection to `script`.
    async fn fake<F, Fut>(script: F) -> (tempfile::TempDir, std::path::PathBuf)
    where
        F: FnOnce(BufReader<OwnedReadHalf>, OwnedWriteHalf) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("qmp.sock");
        let listener = UnixListener::bind(&path).unwrap();
        tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            let (r, mut w) = s.into_split();
            let mut r = BufReader::new(r);
            w.write_all(format!("{GREETING}\n").as_bytes())
                .await
                .unwrap();
            let mut line = String::new();
            r.read_line(&mut line).await.unwrap();
            assert!(line.contains("qmp_capabilities"));
            w.write_all(b"{\"return\": {}}\n").await.unwrap();
            script(r, w).await;
        });
        (dir, path)
    }

    async fn next_request(r: &mut BufReader<OwnedReadHalf>) -> Value {
        let mut line = String::new();
        r.read_line(&mut line).await.unwrap();
        serde_json::from_str(&line).unwrap()
    }

    const WAIT: Duration = Duration::from_secs(5);

    #[tokio::test]
    async fn replies_are_matched_by_id_and_events_broadcast() {
        let (_d, path) = fake(|mut r, mut w| async move {
            let a = next_request(&mut r).await;
            let b = next_request(&mut r).await;
            // Answer out of order, with an event in between.
            let reply = |req: &Value| {
                format!(
                    "{{\"return\": {{\"cmd\": {}}}, \"id\": {}}}\n",
                    req["execute"], req["id"]
                )
            };
            w.write_all(reply(&b).as_bytes()).await.unwrap();
            w.write_all(b"{\"event\": \"STOP\", \"data\": {}, \"timestamp\": {}}\n")
                .await
                .unwrap();
            w.write_all(reply(&a).as_bytes()).await.unwrap();
            std::future::pending::<()>().await;
        })
        .await;

        let qmp = Qmp::connect(&path, WAIT).await.unwrap();
        let mut events = qmp.events();
        let (a, b) = tokio::join!(
            qmp.execute("query-status", None),
            qmp.execute("query-name", Some(json!({})))
        );
        assert_eq!(a.unwrap()["cmd"], "query-status");
        assert_eq!(b.unwrap()["cmd"], "query-name");
        let ev = events.recv().await.unwrap();
        assert_eq!(ev.event, "STOP");
        assert_eq!(ev.micros, 0, "no timestamp");
    }

    #[tokio::test]
    async fn error_replies_become_errors() {
        let (_d, path) = fake(|mut r, mut w| async move {
            let req = next_request(&mut r).await;
            let msg = json!({"error": {"class": "GenericError", "desc": "nope"}, "id": req["id"]});
            w.write_all(format!("{msg}\n").as_bytes()).await.unwrap();
            std::future::pending::<()>().await;
        })
        .await;
        let qmp = Qmp::connect(&path, WAIT).await.unwrap();
        let err = qmp.execute("stop", None).await.unwrap_err();
        assert!(format!("{err:#}").contains("GenericError: nope"), "{err:#}");
    }

    #[tokio::test]
    async fn oversized_line_closes_the_connection() {
        let (_d, path) = fake(|mut r, mut w| async move {
            let _ = next_request(&mut r).await;
            // 100 MiB without a newline; the client must give up early.
            let chunk = vec![b'x'; 1 << 20];
            for _ in 0..100 {
                if w.write_all(&chunk).await.is_err() {
                    return;
                }
            }
        })
        .await;
        let qmp = Qmp::connect(&path, WAIT).await.unwrap();
        let err = qmp.execute("query-status", None).await.unwrap_err();
        assert!(format!("{err:#}").contains("closed"), "{err:#}");
        assert!(qmp.execute("query-status", None).await.is_err());
    }

    #[tokio::test]
    async fn invalid_json_closes_the_connection() {
        let (_d, path) = fake(|mut r, mut w| async move {
            let _ = next_request(&mut r).await;
            w.write_all(b"{not json\n").await.unwrap();
            std::future::pending::<()>().await;
        })
        .await;
        let qmp = Qmp::connect(&path, WAIT).await.unwrap();
        let mut events = qmp.events();
        let err = qmp.execute("query-status", None).await.unwrap_err();
        assert!(format!("{err:#}").contains("closed"), "{err:#}");
        assert!(matches!(
            events.recv().await,
            Err(broadcast::error::RecvError::Closed)
        ));
    }

    #[tokio::test]
    async fn dropped_command_leaves_nothing_pending() {
        let (_d, path) = fake(|r, w| async move {
            let _keep_open = (r, w);
            std::future::pending::<()>().await;
        })
        .await;
        let qmp = Qmp::connect(&path, WAIT).await.unwrap();
        let fut = qmp.execute("query-status", None);
        // Poll it once so the id is registered, then drop it.
        assert!(
            tokio::time::timeout(Duration::from_millis(20), fut)
                .await
                .is_err()
        );
        assert!(qmp.pending.lock().unwrap().as_ref().unwrap().is_empty());
    }

    #[tokio::test]
    async fn stalled_write_poisons_the_connection() {
        // The fake never reads, so a large command fills the socket buffer.
        let (_d, path) = fake(|r, w| async move {
            let _keep_open = (r, w);
            std::future::pending::<()>().await;
        })
        .await;
        let qmp = Qmp::connect(&path, WAIT).await.unwrap();
        let big = json!({ "x": "y".repeat(8 << 20) });
        let err = qmp
            .execute_timeout("big", Some(big), Duration::from_millis(100))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("timed out"), "{err:#}");
        let err = qmp.execute("query-status", None).await.unwrap_err();
        assert!(format!("{err:#}").contains("broken"), "{err:#}");
    }

    #[tokio::test]
    async fn command_times_out() {
        let (_d, path) = fake(|r, w| async move {
            let _keep_open = (r, w);
            std::future::pending::<()>().await;
        })
        .await;
        let qmp = Qmp::connect(&path, WAIT).await.unwrap();
        let err = qmp
            .execute_timeout("query-status", None, Duration::from_millis(50))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("timed out"), "{err:#}");
        assert!(qmp.pending.lock().unwrap().as_ref().unwrap().is_empty());
    }

    #[tokio::test]
    async fn bad_greeting_and_silent_server_fail_to_connect() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("qmp.sock");
        let listener = UnixListener::bind(&path).unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            s.write_all(b"{\"hello\": 1}\n").await.unwrap();
            let (_s2, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        });
        assert!(Qmp::connect(&path, WAIT).await.is_err());
        let err = Qmp::connect(&path, Duration::from_millis(100))
            .await
            .err()
            .unwrap();
        assert!(err.to_string().contains("timed out"), "{err:#}");
    }
}
