//! The daemon API: one JSON request line and one JSON response line per
//! connection, over a Unix socket. `import_iso` alone has a body: the ISO's
//! raw bytes follow its request line. Peers are authorised by their kernel
//! credentials (`SO_PEERCRED`), never by anything they send.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::net::unix::OwnedReadHalf;

use crate::config::{NetProfile, PortForward};
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
    /// Create, start and (with `wait`) wait for the guest agent. `wait`
    /// is ignored for images without one (`images::has_agent`), as for
    /// `Start`.
    New {
        name: String,
        image: String,
        vcpus: u32,
        memory_mib: u64,
        disk_gib: u64,
        net: NetProfile,
        /// Host ports forwarded into the guest (`internet` only).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        forwards: Vec<PortForward>,
        wait: bool,
        /// A VNC socket from the first start (humans only, as `SetVnc`).
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        vnc: bool,
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
    /// Turns a VM's VNC socket on or off from its next start (humans only).
    SetVnc {
        name: String,
        on: bool,
    },
    /// Puts a pulled installer ISO into the CD-ROM drive of a VM made from
    /// an ISO, or empties the drive (`iso: None`), from the VM's next start
    /// (humans only).
    SetCdrom {
        name: String,
        iso: Option<String>,
    },
    /// Changes a stopped VM's vCPUs and/or memory (humans only).
    SetResources {
        name: String,
        vcpus: Option<u32>,
        memory_mib: Option<u64>,
    },
    Host,
    Images,
    Pull {
        image: String,
    },
    /// Deletes a cached image no VM uses (humans only).
    ImageRm {
        image: String,
    },
    /// Imports an installer ISO (humans only): exactly `size` raw bytes
    /// follow the request line, then the client half-closes. `id` starts
    /// with `local-`; `name` is a label.
    ImportIso {
        id: String,
        os: crate::images::Os,
        name: String,
        size: u64,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forwards: Vec<PortForward>,
    pub agent_control: bool,
    #[serde(default)]
    pub vnc: bool,
    /// The image the VM was made from (an older stallod does not send it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// The installer ISO in the CD-ROM drive (VMs made from an ISO).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cdrom: Option<String>,
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
    /// The VNC socket, while the VM runs with VNC (`vnc` in the config may
    /// differ until the next start).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vnc_socket: Option<std::path::PathBuf>,
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
    /// The image and its guest-agent packages are downloaded and verified.
    pub cached: bool,
    // Optional: an older stallod does not send these.
    #[serde(default)]
    pub kind: Option<crate::images::Kind>,
    #[serde(default)]
    pub os: Option<crate::images::Os>,
    #[serde(default)]
    pub trust: Option<crate::images::Trust>,
    /// Bytes of the cached image file.
    #[serde(default)]
    pub size_bytes: Option<u64>,
    /// Date of the signature the cached image was verified with
    /// (`YYYY-MM-DD`), if the pull recorded one.
    #[serde(default)]
    pub sig_date: Option<String>,
    /// Things to know before using the image.
    #[serde(default)]
    pub notes: Vec<String>,
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
        // VNC input bypasses agent control and the audit log (as SetVnc).
        New { vnc: true, .. } => Gate::Closed,
        // A VM from an installer ISO is installed by hand over VNC. Fail
        // closed: only images known to be cloud images pass.
        New { image, .. }
            if !crate::images::find(image)
                .is_ok_and(|e| e.kind == crate::images::Kind::CloudImage) =>
        {
            Gate::Closed
        }
        New { .. } => Gate::Create,
        Rm { .. }
        | Pull { .. }
        | ImageRm { .. }
        // An ISO is untrusted guest input that a human chooses.
        | ImportIso { .. }
        | Resume { .. }
        | SetAgent { .. }
        | SetVnc { .. }
        // What a VM boots from is a human's choice, as at `new`.
        | SetCdrom { .. }
        // Growing a VM takes host CPU and memory budget that a human sized;
        // agent control of a small VM must not let an agent claim the host.
        | SetResources { .. }
        | SnapshotDelete { .. } => Gate::Closed,
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
/// production) a member of the daemon's group. `peer_gids` are the peer's
/// primary and supplementary groups at `connect()` time.
pub fn authorize(peer_uid: u32, peer_gids: &[u32], own_uid: u32, group: Option<u32>) -> bool {
    peer_uid == own_uid || peer_uid == 0 || group.is_some_and(|g| peer_gids.contains(&g))
}

/// The supplementary groups of a Unix socket's peer, as they were at
/// `connect()` (`SO_PEERGROUPS`).
pub fn peer_groups(fd: impl std::os::fd::AsFd) -> std::io::Result<Vec<u32>> {
    use std::os::fd::AsRawFd;
    // Most users are in a few groups; the kernel reports the size it needs
    // (ERANGE) when there are more. NGROUPS_MAX bounds it.
    let mut groups = vec![0 as libc::gid_t; 32];
    loop {
        let mut len = (groups.len() * size_of::<libc::gid_t>()) as libc::socklen_t;
        // SAFETY: `groups` is a writable buffer of `len` bytes, and the
        // kernel writes at most `len` bytes into it.
        #[allow(unsafe_code)]
        let r = unsafe {
            libc::getsockopt(
                fd.as_fd().as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERGROUPS,
                groups.as_mut_ptr().cast(),
                &mut len,
            )
        };
        let need = len as usize / size_of::<libc::gid_t>();
        if r == 0 {
            groups.truncate(need);
            return Ok(groups);
        }
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::ERANGE) || need <= groups.len() || need > 65536 {
            return Err(e);
        }
        groups.resize(need, 0);
    }
}

/// Sends one request and reads the response (client side).
pub async fn call(socket: &Path, envelope: &Envelope) -> Result<serde_json::Value> {
    let (r, mut w) = connect(socket).await?.into_split();
    w.write_all(&request_line(envelope)?).await?;
    response(r).await
}

/// Sends a request with a body (`import_iso`): the request line, all of
/// `body`, then a half-close; and reads the response meanwhile, since the
/// daemon may refuse the request before it reads the body.
pub async fn upload(
    socket: &Path,
    envelope: &Envelope,
    mut body: impl AsyncRead + Unpin,
) -> Result<serde_json::Value> {
    let (r, mut w) = connect(socket).await?.into_split();
    let line = request_line(envelope)?;
    // Owns the write half: if reading `body` fails, dropping it ends the
    // stream, so the daemon sees the import is short at once.
    let send = async move {
        w.write_all(&line).await?;
        tokio::io::copy(&mut body, &mut w).await?;
        w.shutdown().await
    };
    let (sent, answer) = tokio::join!(send, response(r));
    // A refusal closes the connection: its answer says more than the
    // broken pipe.
    let data = answer?;
    sent.context("cannot send the body to stallod")?;
    Ok(data)
}

async fn connect(socket: &Path) -> Result<UnixStream> {
    UnixStream::connect(socket).await.with_context(|| {
        format!(
            "cannot reach stallod at {}; is it running?",
            socket.display()
        )
    })
}

fn request_line(envelope: &Envelope) -> Result<Vec<u8>> {
    let mut line = serde_json::to_vec(envelope)?;
    line.push(b'\n');
    Ok(line)
}

async fn response(r: OwnedReadHalf) -> Result<serde_json::Value> {
    let mut line = Vec::new();
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
        // `vnc` is left out when off (older daemons refuse unknown keys)
        // and defaults to off.
        let new = r#"{"op":"new","name":"a","image":"arch","vcpus":1,"memory_mib":512,"disk_gib":10,"net":"offline","wait":true}"#;
        let r: Request = serde_json::from_str(new).unwrap();
        assert!(matches!(r, Request::New { vnc: false, .. }));
        assert_eq!(serde_json::to_string(&r).unwrap(), new);
        let r: Request = serde_json::from_str(&new.replace('}', r#","vnc":true}"#)).unwrap();
        assert!(matches!(r, Request::New { vnc: true, .. }));
        let resize = r#"{"op":"set_resources","name":"dev","vcpus":4,"memory_mib":null}"#;
        let r: Request = serde_json::from_str(resize).unwrap();
        assert_eq!(serde_json::to_string(&r).unwrap(), resize);
        let eject = r#"{"op":"set_cdrom","name":"dev","iso":null}"#;
        let r: Request = serde_json::from_str(eject).unwrap();
        assert_eq!(serde_json::to_string(&r).unwrap(), eject);
        // A VM from an older stallod has no image or CD-ROM drive.
        let old = r#"{"name":"dev","state":"stopped","vcpus":1,"memory_mib":512,"disk_gib":10,"net":"offline","agent_control":false}"#;
        let vm: VmInfo = serde_json::from_str(old).unwrap();
        assert_eq!((vm.image, vm.cdrom), (None, None));
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
        // image_list reads only the catalog and cache; pulling stays human,
        // also through `new` (the daemon refuses images that are not cached).
        assert_eq!(agent_gate(&Request::Images), Gate::Open);
        assert_eq!(
            agent_gate(&Request::Pull {
                image: "ubuntu-26.04".into()
            }),
            Gate::Closed
        );
        assert_eq!(
            agent_gate(&Request::ImageRm {
                image: "ubuntu-26.04".into()
            }),
            Gate::Closed
        );
        assert_eq!(
            agent_gate(&Request::SetAgent {
                name: name(),
                on: true
            }),
            Gate::Closed
        );
        assert_eq!(agent_gate(&Request::Rm { name: name() }), Gate::Closed);
        // VNC bypasses agent control and the audit log: humans only.
        assert_eq!(
            agent_gate(&Request::SetVnc {
                name: name(),
                on: true
            }),
            Gate::Closed
        );
        assert_eq!(
            agent_gate(&Request::SetResources {
                name: name(),
                vcpus: None,
                memory_mib: Some(4096)
            }),
            Gate::Closed
        );
        for iso in [None, Some("fedora-44-workstation".into())] {
            assert_eq!(
                agent_gate(&Request::SetCdrom { name: name(), iso }),
                Gate::Closed
            );
        }
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

    /// Importing an ISO, or creating a VM from one, is for humans only.
    #[test]
    fn import_gates() {
        let import = Request::ImportIso {
            id: "local-win11".into(),
            os: crate::images::Os::Windows,
            name: "Win11".into(),
            size: 1 << 30,
        };
        assert_eq!(agent_gate(&import), Gate::Closed);
        let e = check_agent(Via::Mcp, &import, true, |_| Ok(true)).unwrap_err();
        assert!(e.to_string().contains("only available to humans"));
        check_agent(Via::Cli, &import, false, |_| Ok(false)).unwrap();
        let new = Request::New {
            name: "win".into(),
            image: "local-win11".into(),
            vcpus: 2,
            memory_mib: 4096,
            disk_gib: 64,
            net: NetProfile::Offline,
            forwards: vec![],
            wait: false,
            vnc: false,
        };
        assert_eq!(agent_gate(&new), Gate::Closed);
        let wire = r#"{"op":"import_iso","id":"local-win11","os":"windows","name":"Win11","size":1073741824}"#;
        assert_eq!(serde_json::to_string(&import).unwrap(), wire);
    }

    /// `upload` sends the line and the body, and shows a refusal that
    /// comes before the body is read (not the broken pipe).
    #[tokio::test]
    async fn upload_body_and_early_refusal() {
        use tokio::io::AsyncReadExt;
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("api.sock");
        let listener = tokio::net::UnixListener::bind(&sock).unwrap();
        let env = Envelope {
            via: Via::Cli,
            request: Request::Images,
        };
        let body = vec![7u8; 4 << 20];
        let server = tokio::spawn(async move {
            // Reads it all.
            let (s, _) = listener.accept().await.unwrap();
            let (r, mut w) = s.into_split();
            let mut r = BufReader::new(r);
            let mut line = Vec::new();
            assert!(read_line(&mut r, &mut line, MAX_REQUEST).await.unwrap());
            let mut got = Vec::new();
            r.read_to_end(&mut got).await.unwrap();
            let reply = format!("{{\"ok\":true,\"data\":{}}}\n", got.len());
            w.write_all(reply.as_bytes()).await.unwrap();
            // Refuses after the request line.
            let (s, _) = listener.accept().await.unwrap();
            let (r, mut w) = s.into_split();
            let mut r = BufReader::new(r);
            assert!(read_line(&mut r, &mut line, MAX_REQUEST).await.unwrap());
            w.write_all(b"{\"ok\":false,\"error\":\"refused\"}\n")
                .await
                .unwrap();
        });
        let v = upload(&sock, &env, &body[..]).await.unwrap();
        assert_eq!(v, serde_json::json!(4 << 20));
        let e = upload(&sock, &env, &body[..]).await.unwrap_err();
        assert_eq!(e.to_string(), "refused");
        server.await.unwrap();
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
            forwards: vec![],
            wait: true,
            vnc: false,
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
        // VNC at create is for humans only, even where agents may create.
        let mut new_vnc = new.clone();
        if let Request::New { vnc, .. } = &mut new_vnc {
            *vnc = true;
        }
        assert!(err(Via::Mcp, &new_vnc, true, on).contains("only available to humans"));
        assert!(check_agent(Via::Cli, &new_vnc, false, off).is_ok());
        // Nor may agents create VMs from installer ISOs, or from images this
        // build does not know.
        for image in ["fedora-44-workstation", "ubuntu-26.04-desktop", "nope"] {
            let mut iso = new.clone();
            if let Request::New { image: i, .. } = &mut iso {
                *i = image.into();
            }
            assert_eq!(agent_gate(&iso), Gate::Closed, "{image}");
            assert!(err(Via::Mcp, &iso, true, on).contains("only available to humans"));
            assert!(check_agent(Via::Cli, &iso, false, off).is_ok());
        }
        let resize = Request::SetResources {
            name: "dev".into(),
            vcpus: Some(4),
            memory_mib: None,
        };
        assert!(err(Via::Mcp, &resize, true, on).contains("only available to humans"));
        assert!(check_agent(Via::Cli, &resize, false, off).is_ok());
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
        assert!(authorize(1000, &[1000], 1000, None));
        assert!(authorize(0, &[0], 1000, None));
        assert!(!authorize(1001, &[1001], 1000, None));
        // Sharing the daemon user's group means nothing in dev mode.
        assert!(!authorize(1001, &[1000, 990], 1000, None));
        assert!(authorize(1001, &[990], 991, Some(990)));
        // Group membership via a supplementary group.
        assert!(authorize(1001, &[1001, 27, 990], 991, Some(990)));
        assert!(!authorize(1001, &[1001, 27], 991, Some(990)));
        assert!(!authorize(1001, &[], 991, Some(990)));
    }

    /// S2: the peer's supplementary groups come from the kernel.
    #[test]
    fn peer_groups_of_own_socket() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut got = peer_groups(&a).unwrap();
        let mut want: Vec<u32> = rustix::process::getgroups()
            .unwrap()
            .into_iter()
            .map(|g| g.as_raw())
            .collect();
        got.sort_unstable();
        want.sort_unstable();
        assert_eq!(got, want);
    }
}
