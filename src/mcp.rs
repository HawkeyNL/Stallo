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

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerConfig};
use rmcp::schemars::{self, JsonSchema};
use rmcp::{ErrorData, ServerHandler, ServiceExt, tool, tool_handler, tool_router};
use serde::Deserialize;
use serde_json::json;
use tokio::io::{AsyncRead, ReadBuf};
use tokio::sync::Semaphore;

use crate::api::{self, Envelope, Request, Via};

/// Longest MCP message line accepted from the client.
pub const MAX_MESSAGE: usize = 16 << 20;
/// Daemon requests in flight at once, so one agent cannot take every
/// daemon connection from the humans.
const MAX_IN_FLIGHT: usize = 8;

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
            .map_err(|_| {
                anyhow::anyhow!(
                    "stallod did not answer within {limit:?}; the operation may still complete, so check the VM before retrying"
                )
            })?
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

/// A tool result: JSON text on success (`ok` when there is nothing to
/// return), the daemon's one-line error (with its hint) as a tool error the
/// agent can read.
fn text_result(result: anyhow::Result<serde_json::Value>) -> CallToolResult {
    match result {
        Ok(serde_json::Value::Null) => CallToolResult::success(vec![ContentBlock::text("ok")]),
        Ok(v) => CallToolResult::success(vec![ContentBlock::text(v.to_string())]),
        Err(e) => error(e),
    }
}

fn error(e: anyhow::Error) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(format!("{e:#}"))])
}

/// A screenshot from the daemon as an image plus its size (and, for
/// `wait_for_screen`, whether it settled).
fn image_result(result: anyhow::Result<serde_json::Value>) -> CallToolResult {
    let shot = match result.and_then(|v| Ok(serde_json::from_value::<api::ScreenResult>(v)?)) {
        Ok(s) => s,
        Err(e) => return error(e),
    };
    let mut text = format!("{}x{}", shot.width, shot.height);
    match shot.stable {
        Some(true) => text.push_str(", stable"),
        Some(false) => text.push_str(", still changing (timed out)"),
        None => {}
    }
    CallToolResult::success(vec![
        ContentBlock::image(shot.png_base64, "image/png"),
        ContentBlock::text(text),
    ])
}

/// Most bytes `file_write` takes in one call (sent in appended chunks).
const MAX_WRITE: usize = 8 << 20;
/// Most stdin bytes for `exec` (one daemon request is at most 1 MiB).
const MAX_STDIN: usize = 512 << 10;

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct VmArgs {
    /// VM name.
    vm: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct CreateArgs {
    /// Name for the new VM: a-z, 0-9 and '-', starting with a letter.
    name: String,
    /// Image id (default ubuntu-26.04).
    image: Option<String>,
    /// Virtual CPUs (default 2).
    vcpus: Option<u32>,
    /// Memory in MiB (default 2048).
    memory_mib: Option<u64>,
    /// Disk size in GiB (default 20).
    disk_gib: Option<u64>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct StartArgs {
    /// VM name.
    vm: String,
    /// Wait until the guest is ready (default true).
    wait: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct StopArgs {
    /// VM name.
    vm: String,
    /// Kill at once instead of an ACPI power-off (default false).
    force: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct PointArgs {
    /// VM name.
    vm: String,
    /// Pixel column in the last screenshot.
    x: u32,
    /// Pixel row in the last screenshot.
    y: u32,
}

#[derive(Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
enum ButtonArg {
    Left,
    Right,
    Middle,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ClickArgs {
    /// VM name.
    vm: String,
    /// Pixel column in the last screenshot.
    x: u32,
    /// Pixel row in the last screenshot.
    y: u32,
    /// Mouse button (default left).
    button: Option<ButtonArg>,
    /// Double click (default false).
    double: Option<bool>,
    /// Return a screenshot taken just after the click (default false).
    screenshot: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct DragArgs {
    /// VM name.
    vm: String,
    /// Start: pixel column in the last screenshot.
    from_x: u32,
    /// Start: pixel row in the last screenshot.
    from_y: u32,
    /// End: pixel column in the last screenshot.
    to_x: u32,
    /// End: pixel row in the last screenshot.
    to_y: u32,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ScrollArgs {
    /// VM name.
    vm: String,
    /// Pixel column in the last screenshot.
    x: u32,
    /// Pixel row in the last screenshot.
    y: u32,
    /// Wheel steps, -50..=50: positive scrolls down, negative up.
    dy: i32,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct TypeArgs {
    /// VM name.
    vm: String,
    /// Up to 1024 characters of printable ASCII, newline and tab (US
    /// keyboard). Use file_write for anything else.
    text: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct KeyArgs {
    /// VM name.
    vm: String,
    /// Keys joined with '+', modifiers first, e.g. "enter", "ctrl+c",
    /// "ctrl+alt+t", "shift+f10". Names: ctrl, alt, altgr, shift, super,
    /// enter, esc, tab, space, backspace, delete, insert, home, end, pageup,
    /// pagedown, up, down, left, right, menu, print, f1-f12, plus, or any
    /// single printable character.
    keys: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct WaitArgs {
    /// VM name.
    vm: String,
    /// How long the screen must stay the same, in ms: 250-60000 (default
    /// 1000).
    stable_ms: Option<u64>,
    /// Give up after this many ms and return the screen anyway: at least
    /// stable_ms, at most 300000 (default 30000).
    timeout_ms: Option<u64>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ExecArgs {
    /// VM name.
    vm: String,
    /// Program and arguments, e.g. ["ls", "-l", "/tmp"]. No shell: use
    /// ["sh", "-c", "..."] for pipes.
    argv: Vec<String>,
    /// Run as root instead of the guest user (default false).
    admin: Option<bool>,
    /// Kill the command after this many seconds: 1-3600 (default 120).
    timeout_s: Option<u64>,
    /// Text for the command's standard input (at most 512 KiB).
    stdin: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ReadArgs {
    /// VM name.
    vm: String,
    /// Absolute path in the guest.
    path: String,
    /// Most bytes to return (default 1 MiB, max 16 MiB - 1).
    max_bytes: Option<u64>,
    /// Start at this byte (default 0). To continue a long file, pass
    /// offset + bytes of the previous part.
    offset: Option<u64>,
    /// Read as root instead of the guest user (default false).
    admin: Option<bool>,
}

#[derive(Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
enum Encoding {
    Utf8,
    Base64,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct WriteArgs {
    /// VM name.
    vm: String,
    /// Absolute path in the guest.
    path: String,
    /// The content (at most 8 MiB).
    data: String,
    /// How `data` is encoded (default utf8).
    encoding: Option<Encoding>,
    /// Append instead of replacing the file (default false).
    append: Option<bool>,
    /// Write as root instead of the guest user (default false).
    admin: Option<bool>,
}

/// Daemon time limits as seen by the adapter: the daemon's own worst case
/// (waiting for an earlier operation on the VM, connecting to the guest
/// agent, a grace period) plus slack. The daemon finishes a request even
/// if the adapter gives up, so these must not be shorter.
const QUICK: Duration = Duration::from_secs(90);
const FILE: Duration = Duration::from_secs(300);
const EXEC_OVERHEAD: Duration = Duration::from_secs(150);

impl Server {
    async fn text(&self, request: Request, limit: Duration) -> Result<CallToolResult, ErrorData> {
        Ok(text_result(self.call(request, limit).await))
    }
}

#[tool_router]
impl Server {
    #[tool(
        description = "List all VMs (name, state, vcpus, memory, network profile, whether agent control is on) and the host's free resources.",
        annotations(read_only_hint = true)
    )]
    async fn vm_list(&self) -> Result<CallToolResult, ErrorData> {
        let result = async {
            let vms = self.call(Request::List, QUICK).await?;
            let host = self.call(Request::Host, QUICK).await?;
            Ok(json!({"vms": vms, "host": host}))
        };
        Ok(text_result(result.await))
    }

    #[tool(
        description = "Details of one VM: state, size, disk use and the guest's IP addresses (null if the guest agent is busy or not answering).",
        annotations(read_only_hint = true)
    )]
    async fn vm_info(
        &self,
        Parameters(a): Parameters<VmArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.text(Request::Info { name: a.vm }, QUICK).await
    }

    #[tool(
        description = "Create an offline VM, start it and wait until it is ready. Only works if the host allows agents to create VMs."
    )]
    async fn vm_create(
        &self,
        Parameters(a): Parameters<CreateArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let request = Request::New {
            name: a.name,
            image: a.image.unwrap_or_else(|| "ubuntu-26.04".into()),
            vcpus: a.vcpus.unwrap_or(2),
            memory_mib: a.memory_mib.unwrap_or(2048),
            disk_gib: a.disk_gib.unwrap_or(20),
            net: crate::config::NetProfile::Offline,
            wait: true,
        };
        // An image download plus first boot.
        self.text(request, Duration::from_secs(1200)).await
    }

    #[tool(description = "Start a stopped VM; by default waits until the guest is ready.")]
    async fn vm_start(
        &self,
        Parameters(a): Parameters<StartArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let request = Request::Start {
            name: a.vm,
            wait: a.wait.unwrap_or(true),
        };
        self.text(request, crate::vm::READY_TIMEOUT + QUICK).await
    }

    #[tool(
        description = "Power a VM off (ACPI, forced after 60 s), or kill it at once with force.",
        annotations(destructive_hint = true)
    )]
    async fn vm_stop(
        &self,
        Parameters(a): Parameters<StopArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let request = Request::Stop {
            name: a.vm,
            force: a.force.unwrap_or(false),
        };
        self.text(request, Duration::from_secs(180)).await
    }

    #[tool(
        description = "Hard-reset a running VM, like pressing its reset button. Unsaved guest work is lost.",
        annotations(destructive_hint = true)
    )]
    async fn vm_reset(
        &self,
        Parameters(a): Parameters<VmArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.text(Request::Reset { name: a.vm }, QUICK).await
    }

    #[tool(
        description = "Take a screenshot of the VM's screen (PNG). Pointer coordinates are pixels of this image.",
        annotations(read_only_hint = true)
    )]
    async fn screenshot(
        &self,
        Parameters(a): Parameters<VmArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        Ok(image_result(
            self.call(Request::Screenshot { name: a.vm }, QUICK).await,
        ))
    }

    #[tool(
        description = "Wait until the screen stops changing (a blinking cursor is ignored), then return a screenshot. Use after typing or clicking, and before typing into a console that is still starting.",
        annotations(read_only_hint = true)
    )]
    async fn wait_for_screen(
        &self,
        Parameters(a): Parameters<WaitArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let stable = a
            .stable_ms
            .map_or(crate::vm::SCREEN_DEFAULT_STABLE, Duration::from_millis);
        let limit = a.timeout_ms.map_or(
            crate::vm::SCREEN_DEFAULT_TIMEOUT.max(stable),
            Duration::from_millis,
        );
        let request = Request::WaitForScreen {
            name: a.vm,
            stable_ms: a.stable_ms,
            timeout_ms: a.timeout_ms,
        };
        Ok(image_result(self.call(request, limit + QUICK).await))
    }

    #[tool(description = "Move the mouse pointer to pixel (x, y) of the last screenshot.")]
    async fn mouse_move(
        &self,
        Parameters(a): Parameters<PointArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.text(
            Request::MouseMove {
                name: a.vm,
                x: a.x,
                y: a.y,
            },
            QUICK,
        )
        .await
    }

    #[tool(
        description = "Click at pixel (x, y) of the last screenshot. Optionally double-click, use another button, or get a screenshot right after."
    )]
    async fn click(
        &self,
        Parameters(a): Parameters<ClickArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let button = match a.button.unwrap_or(ButtonArg::Left) {
            ButtonArg::Left => api::Button::Left,
            ButtonArg::Right => api::Button::Right,
            ButtonArg::Middle => api::Button::Middle,
        };
        let screenshot = a.screenshot.unwrap_or(false);
        let request = Request::Click {
            name: a.vm,
            x: a.x,
            y: a.y,
            button: Some(button),
            double: a.double.unwrap_or(false),
            screenshot,
        };
        let result = self.call(request, QUICK).await;
        Ok(if screenshot {
            image_result(result)
        } else {
            text_result(result)
        })
    }

    #[tool(
        description = "Drag with the left button from (from_x, from_y) to (to_x, to_y), pixels of the last screenshot."
    )]
    async fn drag(&self, Parameters(a): Parameters<DragArgs>) -> Result<CallToolResult, ErrorData> {
        let request = Request::Drag {
            name: a.vm,
            from_x: a.from_x,
            from_y: a.from_y,
            to_x: a.to_x,
            to_y: a.to_y,
        };
        self.text(request, QUICK).await
    }

    #[tool(
        description = "Scroll the mouse wheel at (x, y): positive dy scrolls down, negative up."
    )]
    async fn scroll(
        &self,
        Parameters(a): Parameters<ScrollArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.text(
            Request::Scroll {
                name: a.vm,
                x: a.x,
                y: a.y,
                dy: a.dy,
            },
            QUICK,
        )
        .await
    }

    #[tool(
        description = "Type text on the VM's keyboard (US layout): printable ASCII, newline (enter) and tab, up to 1024 characters. Takes about 15 ms per character."
    )]
    async fn type_text(
        &self,
        Parameters(a): Parameters<TypeArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.text(
            Request::TypeText {
                name: a.vm,
                text: a.text,
            },
            QUICK,
        )
        .await
    }

    #[tool(
        description = "Press a key or key chord, e.g. \"enter\", \"ctrl+c\", \"ctrl+alt+t\", \"alt+f4\"."
    )]
    async fn key(&self, Parameters(a): Parameters<KeyArgs>) -> Result<CallToolResult, ErrorData> {
        self.text(
            Request::Key {
                name: a.vm,
                keys: a.keys,
            },
            QUICK,
        )
        .await
    }

    #[tool(
        description = "Run a program in the guest and return exit_code, stdout and stderr (each cut at 1 MiB, with a truncated flag). Output arrives when the program exits.",
        annotations(destructive_hint = true)
    )]
    async fn exec(&self, Parameters(a): Parameters<ExecArgs>) -> Result<CallToolResult, ErrorData> {
        if a.stdin.as_ref().is_some_and(|s| s.len() > MAX_STDIN) {
            return Ok(error(anyhow::anyhow!(
                "stdin is larger than {MAX_STDIN} bytes; use file_write"
            )));
        }
        let timeout = a
            .timeout_s
            .map_or(crate::vm::EXEC_DEFAULT_TIMEOUT, Duration::from_secs);
        let request = Request::Exec {
            name: a.vm,
            argv: a.argv,
            admin: a.admin.unwrap_or(false),
            timeout_s: Some(timeout.as_secs()),
            stdin: a.stdin,
        };
        let limit = timeout.min(crate::vm::EXEC_MAX_TIMEOUT) + EXEC_OVERHEAD;
        self.text(request, limit).await
    }

    #[tool(
        description = "Read a file in the guest. Returns {encoding: utf8, text} or, for binary data, {encoding: base64, data}, plus bytes (in this part) and more (the file goes on: read again from offset + bytes).",
        annotations(read_only_hint = true)
    )]
    async fn file_read(
        &self,
        Parameters(a): Parameters<ReadArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let request = Request::FileRead {
            name: a.vm,
            path: a.path,
            offset: a.offset.unwrap_or(0),
            max_bytes: a.max_bytes,
            admin: a.admin.unwrap_or(false),
        };
        let result = async {
            let v = self.call(request, FILE).await?;
            let part: api::FileData = serde_json::from_value(v)?;
            let bytes = BASE64.decode(&part.data_base64)?;
            Ok(match String::from_utf8(bytes) {
                Ok(text) => {
                    json!({"encoding": "utf8", "text": text, "bytes": part.size, "more": part.more})
                }
                Err(_) => {
                    json!({"encoding": "base64", "data": part.data_base64, "bytes": part.size, "more": part.more})
                }
            })
        };
        Ok(text_result(result.await))
    }

    #[tool(
        description = "Write a file in the guest (replace or append), as the guest user unless admin. Writes over 512 KiB go in parts and are not atomic.",
        annotations(destructive_hint = true)
    )]
    async fn file_write(
        &self,
        Parameters(a): Parameters<WriteArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let result = async {
            let data = match a.encoding.unwrap_or(Encoding::Utf8) {
                Encoding::Utf8 => a.data.into_bytes(),
                Encoding::Base64 => BASE64.decode(&a.data)?,
            };
            anyhow::ensure!(
                data.len() <= MAX_WRITE,
                "at most {MAX_WRITE} bytes per call"
            );
            let append = a.append.unwrap_or(false);
            // The daemon takes requests up to 1 MiB: send appended chunks
            // (an empty file is one empty write).
            let chunks: Vec<&[u8]> = if data.is_empty() {
                vec![&[]]
            } else {
                data.chunks(api::FILE_WRITE_CHUNK).collect()
            };
            let mut sent = 0;
            for (i, chunk) in chunks.into_iter().enumerate() {
                let request = Request::FileWrite {
                    name: a.vm.clone(),
                    path: a.path.clone(),
                    data_base64: BASE64.encode(chunk),
                    append: append || i > 0,
                    admin: a.admin.unwrap_or(false),
                };
                self.call(request, FILE).await.map_err(|e| {
                    if sent > 0 {
                        e.context(format!(
                            "wrote {sent} of {} bytes; {} is partial",
                            data.len(),
                            a.path
                        ))
                    } else {
                        e
                    }
                })?;
                sent += chunk.len();
            }
            Ok(json!({"bytes": sent}))
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
                let reply = match &env.request {
                    Request::List => json!({"ok": true, "data": [{"name": "dev"}]}),
                    Request::Host if !host_fails => json!({"ok": true, "data": {"cores": 16}}),
                    Request::Screenshot { .. } => json!({"ok": true, "data":
                        {"png_base64": "iVBORw0KGgo=", "width": 1280, "height": 800}}),
                    Request::FileRead { path, .. } => {
                        let data: &[u8] = if path == "/bin" {
                            b"\xff\xfe"
                        } else {
                            b"hello"
                        };
                        json!({"ok": true, "data": {"data_base64": BASE64.encode(data),
                            "size": data.len(), "more": false}})
                    }
                    Request::FileWrite { .. } | Request::Key { .. } => json!({"ok": true}),
                    Request::Exec { .. } => json!({"ok": false,
                        "error": "agent control is off for dev; a human can run: stallo agent dev on"}),
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
        let mut want = [
            "vm_list",
            "vm_info",
            "vm_create",
            "vm_start",
            "vm_stop",
            "vm_reset",
            "screenshot",
            "wait_for_screen",
            "mouse_move",
            "click",
            "drag",
            "scroll",
            "type_text",
            "key",
            "exec",
            "file_read",
            "file_write",
        ];
        let mut tools = tools;
        tools.sort();
        want.sort();
        assert_eq!(tools, want);
        // Never a delete or agent-control tool.
        assert!(
            !tools
                .iter()
                .any(|t| t.contains("delete") || t.contains("agent"))
        );
        assert_eq!(r[2]["result"]["isError"], false);
        let text = r[2]["result"]["content"][0]["text"].as_str().unwrap();
        let v: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(v, json!({"vms": [{"name": "dev"}], "host": {"cores": 16}}));
        for _ in 0..2 {
            assert_eq!(seen.recv().await.unwrap().via, Via::Mcp);
        }
    }

    /// Calls `tool` with `args` in a fresh session; returns the result and
    /// the requests the daemon saw.
    async fn tool(name: &str, args: serde_json::Value) -> (serde_json::Value, Vec<Request>) {
        let dir = tempfile::tempdir().unwrap();
        let (socket, mut seen) = fake_daemon(dir.path(), false);
        let mut reqs = init().to_vec();
        reqs.push(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": name, "arguments": args}}));
        let r = session(socket, &reqs).await;
        let mut got = Vec::new();
        while let Ok(env) = seen.try_recv() {
            assert_eq!(env.via, Via::Mcp);
            got.push(env.request);
        }
        (r[1].clone(), got)
    }

    #[tokio::test]
    async fn tools_map_to_daemon_requests() {
        let tool = |name: &'static str, args| async move {
            let (r, seen) = tool(name, args).await;
            (r.get("result").cloned().unwrap_or(r), seen)
        };
        let (r, _) = tool("screenshot", json!({"vm": "dev"})).await;
        assert_eq!(r["content"][0]["type"], "image");
        assert_eq!(r["content"][0]["mimeType"], "image/png");
        assert_eq!(r["content"][1]["text"], "1280x800");

        let (r, _) = tool("file_read", json!({"vm": "dev", "path": "/etc/x"})).await;
        let v: serde_json::Value =
            serde_json::from_str(r["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(
            (v["encoding"].as_str(), v["text"].as_str()),
            (Some("utf8"), Some("hello"))
        );
        let (r, _) = tool("file_read", json!({"vm": "dev", "path": "/bin"})).await;
        let v: serde_json::Value =
            serde_json::from_str(r["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(v["encoding"], "base64");

        // 1.2 MiB goes out in three appended chunks.
        let data = "x".repeat(api::FILE_WRITE_CHUNK * 2 + 10);
        let (r, seen) = tool(
            "file_write",
            json!({"vm": "dev", "path": "/tmp/f", "data": data}),
        )
        .await;
        assert_eq!(r["isError"], false);
        let appends: Vec<bool> = seen
            .iter()
            .map(|r| match r {
                Request::FileWrite { append, .. } => *append,
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(appends, [false, true, true]);
        let (_, seen) = tool(
            "file_write",
            json!({"vm": "dev", "path": "/tmp/e", "data": ""}),
        )
        .await;
        assert_eq!(seen.len(), 1);
        let (r, seen) = tool(
            "file_write",
            json!({"vm": "dev", "path": "/tmp/e", "data": "!", "encoding": "base64"}),
        )
        .await;
        assert_eq!((r["isError"].as_bool(), seen.len()), (Some(true), 0));

        // The daemon's refusal reaches the agent as a tool error.
        let (r, _) = tool("exec", json!({"vm": "dev", "argv": ["true"]})).await;
        assert_eq!(r["isError"], true);
        assert!(
            r["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("agent control is off")
        );
        // Bad arguments never reach the daemon.
        let (r, seen) = tool(
            "click",
            json!({"vm": "dev", "x": 1, "y": 1, "button": "side"}),
        )
        .await;
        assert_eq!((r["isError"].as_bool(), seen.len()), (Some(true), 0));
        let (r, seen) = tool("key", json!({"vm": "dev", "keys": "enter", "extra": 1})).await;
        assert!(r.get("result").is_none() || r["isError"] == true, "{r}");
        assert!(seen.is_empty());
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
