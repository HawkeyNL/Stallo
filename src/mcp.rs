//! `stallo mcp`: an MCP server on stdio for AI agents. It adapts tool calls
//! to the daemon API with `via: mcp`. Policy (which VMs agents may control)
//! lives in the daemon, so this is a thin client that never touches QEMU,
//! guests or host files.
//!
//! stdout is the protocol: nothing else may write to it. A tracing
//! subscriber in the CLI must write to stderr (rmcp logs requests at debug).

use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::model::{CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerConfig};
use rmcp::{ErrorData, ServerHandler, ServiceExt, tool, tool_handler, tool_router};
use serde_json::json;
use tokio::io::{AsyncRead, ReadBuf};
use tokio::sync::Semaphore;

use crate::api::{self, Envelope, Request, Via};

/// Longest MCP message line accepted from the client.
pub const MAX_MESSAGE: usize = 16 << 20;
/// Daemon requests in flight at once, so one agent cannot take every
/// daemon connection from the humans.
const MAX_IN_FLIGHT: usize = 8;
/// Time limit for quick daemon requests.
const QUICK: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub struct Server {
    socket: PathBuf,
    slots: Arc<Semaphore>,
    tool_router: ToolRouter<Self>,
}

/// Serves MCP on stdin/stdout until the client disconnects or sends a line
/// longer than [`MAX_MESSAGE`].
pub async fn serve_stdio(socket: PathBuf) -> anyhow::Result<()> {
    let stdin = LineCap::new(tokio::io::stdin(), MAX_MESSAGE);
    Server::new(socket)
        .serve((stdin, tokio::io::stdout()))
        .await?
        .waiting()
        .await?;
    Ok(())
}

impl Server {
    pub fn new(socket: PathBuf) -> Self {
        Self {
            socket,
            slots: Arc::new(Semaphore::new(MAX_IN_FLIGHT)),
            tool_router: Self::tool_router(),
        }
    }

    /// One daemon request as an agent, within `limit`.
    async fn call(&self, request: Request, limit: Duration) -> anyhow::Result<serde_json::Value> {
        let _slot = self.slots.acquire().await?;
        let envelope = Envelope {
            via: Via::Mcp,
            request,
        };
        tokio::time::timeout(limit, api::call(&self.socket, &envelope))
            .await
            .map_err(|_| anyhow::anyhow!("stallod did not answer within {limit:?}"))?
    }
}

/// A reader that fails once a line grows past `max` bytes. rmcp reads
/// lines without a limit; this keeps its buffer bounded (the session ends
/// on the error).
pub struct LineCap<R> {
    inner: R,
    max: usize,
    line: usize,
}

impl<R> LineCap<R> {
    pub fn new(inner: R, max: usize) -> Self {
        Self {
            inner,
            max,
            line: 0,
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for LineCap<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let this = &mut *self;
        std::task::ready!(Pin::new(&mut this.inner).poll_read(cx, buf))?;
        for i in before..buf.filled().len() {
            let b = buf.filled()[i];
            this.line = if b == b'\n' { 0 } else { this.line + 1 };
            if this.line > this.max {
                buf.set_filled(before);
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "MCP message too long",
                )));
            }
        }
        Poll::Ready(Ok(()))
    }
}

/// A tool result: JSON text on success, the daemon's one-line error (with
/// its hint) as a tool error the agent can read.
fn text_result(result: anyhow::Result<serde_json::Value>) -> CallToolResult {
    match result {
        Ok(v) => CallToolResult::success(vec![ContentBlock::text(v.to_string())]),
        Err(e) => CallToolResult::error(vec![ContentBlock::text(format!("{e:#}"))]),
    }
}

#[tool_router]
impl Server {
    #[tool(
        description = "List all VMs (name, state, vcpus, memory, network profile, whether agent control is on) and the host's free resources."
    )]
    async fn vm_list(&self) -> Result<CallToolResult, ErrorData> {
        let result = async {
            let vms = self.call(Request::List, QUICK).await?;
            let host = self.call(Request::Host, QUICK).await?;
            Ok(json!({"vms": vms, "host": host}))
        };
        Ok(text_result(result.await))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for Server {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("stallo", env!("CARGO_PKG_VERSION")))
            .with_instructions(
                "Stallo runs local VMs. Agents may only control VMs where a human turned agent control on; if a VM refuses, ask the user.",
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;

    /// A fake daemon: answers `list`, fails `host` if `host_fails`, and
    /// reports every envelope it gets.
    fn fake_daemon(
        dir: &std::path::Path,
        host_fails: bool,
    ) -> (PathBuf, tokio::sync::mpsc::UnboundedReceiver<Envelope>) {
        let path = dir.join("api.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((s, _)) = listener.accept().await {
                let (r, mut w) = s.into_split();
                let mut line = String::new();
                let _ = BufReader::new(r).read_line(&mut line).await;
                let Ok(env) = serde_json::from_str::<Envelope>(&line) else {
                    return;
                };
                let reply = match env.request {
                    Request::List => json!({"ok": true, "data": [{"name": "dev"}]}),
                    Request::Host if !host_fails => json!({"ok": true, "data": {"cores": 16}}),
                    _ => json!({"ok": false, "error": "nope"}),
                };
                let _ = tx.send(env);
                let _ = w.write_all(format!("{reply}\n").as_bytes()).await;
            }
        });
        (path, rx)
    }

    /// Sends JSON-RPC lines to the server and returns its replies with ids.
    async fn session(socket: PathBuf, requests: &[serde_json::Value]) -> Vec<serde_json::Value> {
        let (client, server) = tokio::io::duplex(1 << 16);
        tokio::spawn(async move {
            let running = Server::new(socket).serve(server).await.unwrap();
            let _ = running.waiting().await;
        });
        let (r, mut w) = tokio::io::split(client);
        let mut lines = BufReader::new(r).lines();
        let mut replies = Vec::new();
        for req in requests {
            w.write_all(format!("{req}\n").as_bytes()).await.unwrap();
            if req.get("id").is_some() {
                let line = lines.next_line().await.unwrap().unwrap();
                replies.push(serde_json::from_str(&line).unwrap());
            }
        }
        replies
    }

    fn init() -> [serde_json::Value; 2] {
        [
            json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-06-18", "capabilities": {},
                "clientInfo": {"name": "test", "version": "0"}}}),
            json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        ]
    }

    #[tokio::test]
    async fn lists_tools_and_calls_vm_list() {
        let dir = tempfile::tempdir().unwrap();
        let (socket, mut seen) = fake_daemon(dir.path(), false);
        let mut reqs = init().to_vec();
        reqs.push(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}));
        reqs.push(json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "vm_list", "arguments": {}}}));
        let r = session(socket, &reqs).await;
        assert_eq!(r[0]["result"]["serverInfo"]["name"], "stallo");
        let tools: Vec<&str> = r[1]["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(tools, ["vm_list"]);
        assert_eq!(r[2]["result"]["isError"], false);
        let text = r[2]["result"]["content"][0]["text"].as_str().unwrap();
        let v: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(v, json!({"vms": [{"name": "dev"}], "host": {"cores": 16}}));
        for _ in 0..2 {
            assert_eq!(seen.recv().await.unwrap().via, Via::Mcp);
        }
    }

    #[tokio::test]
    async fn partial_failure_is_a_tool_error() {
        let dir = tempfile::tempdir().unwrap();
        let (socket, _seen) = fake_daemon(dir.path(), true);
        let mut reqs = init().to_vec();
        reqs.push(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "vm_list", "arguments": {}}}));
        let r = session(socket, &reqs).await;
        assert_eq!(r[1]["result"]["isError"], true);
        assert_eq!(r[1]["result"]["content"][0]["text"], "nope");
    }

    #[tokio::test]
    async fn line_cap_ends_long_lines() {
        use tokio::io::AsyncReadExt;
        let mut ok = LineCap::new(&b"abcd\nefgh\n"[..], 4);
        let mut out = Vec::new();
        ok.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"abcd\nefgh\n");
        let mut long = LineCap::new(&b"ab\nabcde"[..], 4);
        let err = long.read_to_end(&mut out).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        // A server fed an endless line stops instead of buffering it.
        let (mut client, server) = tokio::io::duplex(1 << 16);
        let (r, w) = tokio::io::split(server);
        let dir = tempfile::tempdir().unwrap();
        let running = tokio::spawn(async move {
            let s = Server::new(dir.path().join("x.sock"))
                .serve((LineCap::new(r, 1 << 20), w))
                .await;
            if let Ok(s) = s {
                let _ = s.waiting().await;
            }
        });
        let chunk = vec![b'x'; 1 << 16];
        for _ in 0..32 {
            if client.write_all(&chunk).await.is_err() {
                break;
            }
        }
        tokio::time::timeout(Duration::from_secs(5), running)
            .await
            .expect("server did not stop on an oversized line")
            .unwrap();
    }

    #[tokio::test]
    async fn daemon_errors_are_tool_errors() {
        let dir = tempfile::tempdir().unwrap();
        let mut reqs = init().to_vec();
        reqs.push(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "vm_list", "arguments": {}}}));
        let r = session(dir.path().join("missing.sock"), &reqs).await;
        assert_eq!(r[1]["result"]["isError"], true);
        let text = r[1]["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("cannot reach stallod"), "{text}");
    }
}
