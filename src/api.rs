//! The daemon API: one JSON request line and one JSON response line per
//! connection, over a Unix socket. Peers are authorised by their kernel
//! credentials (`SO_PEERCRED`), never by anything they send.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::config::NetProfile;
use crate::read_line;
pub use crate::vm::Button;

/// Longest request line the daemon accepts.
pub const MAX_REQUEST: usize = 1 << 20;
/// Longest response line the CLI accepts.
pub const MAX_RESPONSE: usize = 32 << 20;
/// A client must send its request within this time.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Who is calling. Client-declared, so it is policy, not a boundary (see
/// SECURITY.md); the socket permissions and peer credentials are.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Via {
    Cli,
    Mcp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub via: Via,
    pub request: Request,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    /// Create, start and (with `wait`) wait for the guest agent.
    New {
        name: String,
        image: String,
        vcpus: u32,
        memory_mib: u64,
        disk_gib: u64,
        net: NetProfile,
        wait: bool,
    },
    List,
    Start {
        name: String,
        wait: bool,
    },
    Stop {
        name: String,
        force: bool,
    },
    Exec {
        name: String,
        argv: Vec<String>,
        admin: bool,
        timeout_s: Option<u64>,
        /// Text for the command's standard input.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stdin: Option<String>,
    },
    /// Runs a command in a throwaway clone of a stopped VM (`stallo run`).
    Run {
        name: String,
        argv: Vec<String>,
        admin: bool,
        timeout_s: Option<u64>,
    },
    /// Reads part of a guest file: up to `max_bytes` (default 1 MiB, at
    /// most 16 MiB) from `offset`.
    FileRead {
        name: String,
        path: String,
        #[serde(default)]
        offset: u64,
        max_bytes: Option<u64>,
        #[serde(default)]
        admin: bool,
    },
    /// Writes a guest file (or appends to it). Requests are capped at
    /// 1 MiB, so larger files go in appended chunks.
    FileWrite {
        name: String,
        path: String,
        data_base64: String,
        #[serde(default)]
        append: bool,
        #[serde(default)]
        admin: bool,
    },
    Rm {
        name: String,
    },
    /// A VM with its guest IP addresses and disk use.
    Info {
        name: String,
    },
    /// Hardware reset.
    Reset {
        name: String,
    },
    Screenshot {
        name: String,
    },
    WaitForScreen {
        name: String,
        stable_ms: Option<u64>,
        timeout_ms: Option<u64>,
    },
    MouseMove {
        name: String,
        x: u32,
        y: u32,
    },
    Click {
        name: String,
        x: u32,
        y: u32,
        button: Option<Button>,
        #[serde(default)]
        double: bool,
        #[serde(default)]
        screenshot: bool,
    },
    Drag {
        name: String,
        from_x: u32,
        from_y: u32,
        to_x: u32,
        to_y: u32,
    },
    Scroll {
        name: String,
        x: u32,
        y: u32,
        dy: i32,
    },
    TypeText {
        name: String,
        text: String,
    },
    Key {
        name: String,
        keys: String,
    },
    Resume {
        name: String,
    },
    /// Takes a snapshot (default name `snap<N>`); with RAM if the VM runs.
    Snapshot {
        name: String,
        tag: Option<String>,
    },
    /// Lists a VM's snapshots, oldest first.
    Snapshots {
        name: String,
    },
    /// Restores a snapshot (default: the newest).
    Restore {
        name: String,
        tag: Option<String>,
    },
    /// Deletes a snapshot (humans only).
    SnapshotDelete {
        name: String,
        tag: String,
    },
    /// Turns agent control of a VM on or off (humans only).
    SetAgent {
        name: String,
        on: bool,
    },
    Host,
    Images,
    Pull {
        image: String,
    },
}

/// One response line: `{"ok":true,"data":...}` or `{"ok":false,"error":"..."}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub data: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Response {
    pub fn ok<T: Serialize>(data: &T) -> Result<Self> {
        Ok(Self {
            ok: true,
            data: serde_json::to_value(data)?,
            error: None,
        })
    }

    pub fn err(e: &anyhow::Error) -> Self {
        Self {
            ok: false,
            data: serde_json::Value::Null,
            error: Some(format!("{e:#}")),
        }
    }
}

/// A VM as `ls` shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmInfo {
    pub name: String,
    /// `stopped`, or QEMU's run state (`running`, `paused`, `io-error`...).
    pub state: String,
    pub vcpus: u32,
    pub memory_mib: u64,
    pub disk_gib: u64,
    pub net: NetProfile,
    pub agent_control: bool,
}

/// `info`: a VM plus what only a running guest or the disk can tell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmDetails {
    #[serde(flatten)]
    pub vm: VmInfo,
    /// `(interface, address/prefix)`; empty when stopped, `None` when the
    /// guest agent is busy or does not answer.
    pub addresses: Option<Vec<(String, String)>>,
    /// Host disk space the VM's disk uses (its overlay, not the base).
    pub disk_used_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewResult {
    pub vm: VmInfo,
    /// Milliseconds from the start of creation (after any image download)
    /// to guest agent ready, when waited for.
    pub ready_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecResult {
    pub exit_code: i32,
    /// Lossy UTF-8; binary output belongs in `file_read`.
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
}

/// A screenshot: PNG as base64, with its size (coordinates for the input
/// tools are pixels of this image).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScreenResult {
    pub png_base64: String,
    pub width: u32,
    pub height: u32,
    /// `wait_for_screen` only: whether the screen settled in time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stable: Option<bool>,
}

/// Part of a guest file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileData {
    pub data_base64: String,
    /// Bytes in `data_base64`.
    pub size: u64,
    /// The file goes on past this part.
    pub more: bool,
}

/// Default `max_bytes` of a file read (the largest is 16 MiB - 1).
pub const FILE_READ_DEFAULT: u64 = 1 << 20;
/// Raw bytes per `file_write` request: base64 of this plus the envelope
/// stays under [`MAX_REQUEST`].
pub const FILE_WRITE_CHUNK: usize = 512 << 10;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageInfo {
    pub id: String,
    pub name: String,
    pub cached: bool,
}

/// What an agent (`via: mcp`) may do with a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate<'a> {
    /// Reads nothing of any VM's insides.
    Open,
    /// Only if agent control is on for this VM.
    Vm(&'a str),
    /// Only if the daemon allows agents to create VMs.
    Create,
    /// Never: irreversible or policy-changing operations stay with humans.
    Closed,
}

/// The gate for `r` when an agent sends it. Exhaustive on purpose: a new
/// operation must be placed here.
pub fn agent_gate(r: &Request) -> Gate<'_> {
    use Request::*;
    match r {
        List | Host | Images => Gate::Open,
        New { .. } => Gate::Create,
        Rm { .. } | Pull { .. } | Resume { .. } | SetAgent { .. } | SnapshotDelete { .. } => {
            Gate::Closed
        }
        Start { name, .. }
        | Stop { name, .. }
        | Exec { name, .. }
        | Run { name, .. }
        | FileRead { name, .. }
        | FileWrite { name, .. }
        | Screenshot { name }
        | Info { name }
        | Reset { name }
        | WaitForScreen { name, .. }
        | MouseMove { name, .. }
        | Click { name, .. }
        | Drag { name, .. }
        | Scroll { name, .. }
        | TypeText { name, .. }
        | Key { name, .. }
        | Snapshot { name, .. }
        | Snapshots { name }
        | Restore { name, .. } => Gate::Vm(name),
    }
}

/// The agent policy for one request. CLI requests pass; agent (`mcp`)
/// requests pass the [`agent_gate`]. `agent_control` reads a VM's switch.
/// `via` is declared by the client, so this is policy, not a boundary
/// against processes that can reach the socket (see SECURITY.md).
pub fn check_agent(
    via: Via,
    request: &Request,
    agents_can_create: bool,
    agent_control: impl FnOnce(&str) -> Result<bool>,
) -> Result<()> {
    match via {
        Via::Cli => return Ok(()),
        Via::Mcp => {}
    }
    match agent_gate(request) {
        Gate::Open => Ok(()),
        Gate::Create if agents_can_create => Ok(()),
        Gate::Create => bail!("agents may not create VMs on this host (agents_can_create is off)"),
        Gate::Closed => bail!("this operation is only available to humans (stallo CLI)"),
        Gate::Vm(name) if agent_control(name)? => Ok(()),
        Gate::Vm(name) => {
            bail!("agent control is off for {name}; a human can run: stallo agent {name} on")
        }
    }
}

/// Whether a peer may use the API: the daemon's own UID, root, or (in
/// production) a member of the daemon's group via the primary GID.
pub fn authorize(peer_uid: u32, peer_gid: u32, own_uid: u32, group: Option<u32>) -> bool {
    peer_uid == own_uid || peer_uid == 0 || group.is_some_and(|g| g == peer_gid)
}

/// Sends one request and reads the response (client side).
pub async fn call(socket: &Path, envelope: &Envelope) -> Result<serde_json::Value> {
    let stream = UnixStream::connect(socket).await.with_context(|| {
        format!(
            "cannot reach stallod at {}; is it running?",
            socket.display()
        )
    })?;
    let (r, mut w) = stream.into_split();
    let mut line = serde_json::to_vec(envelope)?;
    line.push(b'\n');
    w.write_all(&line).await?;
    let mut r = BufReader::new(r);
    if !read_line(&mut r, &mut line, MAX_RESPONSE).await? {
        bail!("stallod closed the connection without an answer");
    }
    let resp: Response = serde_json::from_slice(&line).context("invalid response from stallod")?;
    match resp.error {
        Some(e) if !resp.ok => bail!("{e}"),
        _ => Ok(resp.data),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_format() {
        let e = Envelope {
            via: Via::Cli,
            request: Request::Stop {
                name: "dev".into(),
                force: false,
            },
        };
        let text = serde_json::to_string(&e).unwrap();
        assert_eq!(
            text,
            r#"{"via":"cli","request":{"op":"stop","name":"dev","force":false}}"#
        );
        assert_eq!(serde_json::from_str::<Envelope>(&text).unwrap(), e);
        // serde cannot reject extra keys on argument-less ops; they are ignored.
        let list = r#"{"via":"mcp","request":{"op":"list"}}"#;
        assert!(serde_json::from_str::<Envelope>(list).is_ok());
        for bad in [
            r#"{"via":"cli","request":{"op":"stop","name":"dev","force":false,"x":1}}"#,
            r#"{"via":"root","request":{"op":"list"}}"#,
            r#"{"via":"cli","request":{"op":"format_host"}}"#,
            r#"{"request":{"op":"list"}}"#,
        ] {
            assert!(serde_json::from_str::<Envelope>(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn agent_gates() {
        let name = || "dev".to_owned();
        assert_eq!(agent_gate(&Request::List), Gate::Open);
        assert_eq!(
            agent_gate(&Request::SetAgent {
                name: name(),
                on: true
            }),
            Gate::Closed
        );
        assert_eq!(agent_gate(&Request::Rm { name: name() }), Gate::Closed);
        assert_eq!(
            agent_gate(&Request::SnapshotDelete {
                name: name(),
                tag: "s1".into()
            }),
            Gate::Closed
        );
        assert_eq!(
            agent_gate(&Request::Restore {
                name: name(),
                tag: None
            }),
            Gate::Vm("dev")
        );
        assert_eq!(
            agent_gate(&Request::TypeText {
                name: name(),
                text: "x".into()
            }),
            Gate::Vm("dev")
        );
        assert_eq!(
            agent_gate(&Request::Screenshot { name: name() }),
            Gate::Vm("dev")
        );
        let run = Request::Run {
            name: name(),
            argv: vec!["true".into()],
            admin: false,
            timeout_s: None,
        };
        assert_eq!(agent_gate(&run), Gate::Vm("dev"));
    }

    /// S8: the policy, without a VM.
    #[test]
    fn agent_policy() {
        let shot = Request::Screenshot { name: "dev".into() };
        let new = Request::New {
            name: "two".into(),
            image: "ubuntu-26.04".into(),
            vcpus: 1,
            memory_mib: 512,
            disk_gib: 10,
            net: NetProfile::Offline,
            wait: true,
        };
        let on = |_: &str| Ok(true);
        let off = |_: &str| Ok(false);
        let err = |via, r: &Request, create, f: fn(&str) -> Result<bool>| {
            check_agent(via, r, create, f).unwrap_err().to_string()
        };
        assert!(check_agent(Via::Cli, &shot, false, off).is_ok());
        assert!(check_agent(Via::Mcp, &shot, false, on).is_ok());
        assert!(err(Via::Mcp, &shot, false, off).contains("agent control is off for dev"));
        assert!(check_agent(Via::Mcp, &shot, false, |_| bail!("no VM")).is_err());
        assert!(check_agent(Via::Mcp, &new, true, off).is_ok());
        assert!(err(Via::Mcp, &new, false, on).contains("agents_can_create"));
        assert!(check_agent(Via::Cli, &new, false, off).is_ok());
        let closed = Request::SetAgent {
            name: "dev".into(),
            on: true,
        };
        assert!(err(Via::Mcp, &closed, true, on).contains("only available to humans"));
        assert!(check_agent(Via::Mcp, &Request::List, false, off).is_ok());
    }

    /// S2.
    #[test]
    fn authorization() {
        assert!(authorize(1000, 1000, 1000, None));
        assert!(authorize(0, 0, 1000, None));
        assert!(!authorize(1001, 1001, 1000, None));
        assert!(!authorize(1001, 1000, 1000, None));
        assert!(authorize(1001, 990, 991, Some(990)));
        assert!(!authorize(1001, 1001, 991, Some(990)));
    }
}
