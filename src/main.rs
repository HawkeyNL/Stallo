//! stallo: the command-line client for stallod.

use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result, bail, ensure};
use clap::{Parser, Subcommand};
use serde_json::Value;

use stallo::api::{self, Envelope, ExecResult, ImageInfo, NewResult, Request, Via, VmInfo};
use stallo::config::NetProfile;
use stallo::host::HostInfo;
use stallo::snapshot::{Restored, Snapshot, Taken};

#[derive(Parser)]
#[command(version, about = "Agent-first VMs on Ubuntu", propagate_version = true)]
struct Cli {
    /// Print machine-readable JSON.
    #[arg(long, global = true)]
    json: bool,
    /// API socket (default: $STALLO_SOCKET, else the production socket
    /// /run/stallo/api.sock if it is there, else the dev-mode socket; with
    /// both daemons running, one must be chosen).
    #[arg(long, global = true)]
    socket: Option<PathBuf>,
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a VM, start it and wait until it is ready.
    New {
        #[arg(default_value = "dev")]
        name: String,
        #[arg(long, default_value = "ubuntu-26.04")]
        image: String,
        #[arg(long, default_value_t = 2)]
        cpus: u32,
        /// Memory, e.g. 2G or 1536M.
        #[arg(long, default_value = "2G", value_parser = parse_mib)]
        mem: u64,
        /// Disk size, e.g. 20G.
        #[arg(long, default_value = "20G", value_parser = parse_gib)]
        disk: u64,
        #[arg(long, value_enum, default_value = "offline")]
        net: Net,
        /// Forward a host TCP port into the guest (`--net internet` only),
        /// e.g. 8080:80. Host ports must be above 1024. Repeatable.
        #[arg(long = "forward", value_name = "HOST:GUEST")]
        forwards: Vec<String>,
        /// Host address the forwarded ports listen on.
        #[arg(long, default_value = "127.0.0.1", requires = "forwards")]
        bind: std::net::IpAddr,
        /// Return once QEMU runs, without waiting for the guest agent.
        #[arg(long)]
        no_wait: bool,
        /// Start with a VNC server (as `stallo set <vm> --vnc on`).
        #[arg(long)]
        vnc: bool,
    },
    /// List VMs.
    Ls,
    /// Start a stopped VM and wait until it is ready.
    Start {
        vm: String,
        #[arg(long)]
        no_wait: bool,
    },
    /// Power a VM off (ACPI, then forced after 60 s).
    Stop {
        vm: String,
        /// Kill at once.
        #[arg(long)]
        force: bool,
    },
    /// Run a command in the guest; its exit code is passed through.
    Exec {
        vm: String,
        /// Run as root instead of the guest user.
        #[arg(long)]
        admin: bool,
        /// Seconds before the command is killed (default 120, max 3600).
        #[arg(long)]
        timeout: Option<u64>,
        #[arg(last = true, required = true)]
        argv: Vec<String>,
    },
    /// Run a command in a throwaway clone of a stopped VM; the clone is
    /// deleted afterwards (also on Ctrl-C). The exit code is passed through.
    Run {
        vm: String,
        /// Run as root instead of the guest user.
        #[arg(long)]
        admin: bool,
        /// Seconds before the command is killed (default 120, max 3600).
        #[arg(long)]
        timeout: Option<u64>,
        #[arg(last = true, required = true)]
        argv: Vec<String>,
    },
    /// Copy a file between the host and a VM, e.g. `stallo cp notes.txt
    /// dev:/home/agent/notes.txt` or `stallo cp dev:/etc/os-release .`.
    Cp {
        src: String,
        dst: String,
        /// Read or write the guest file as root instead of the guest user.
        #[arg(long)]
        admin: bool,
    },
    /// Take a snapshot (with RAM and running programs if the VM runs; disk
    /// only if it is stopped), or delete one.
    Snap {
        vm: String,
        /// Snapshot name (default snap<N>).
        name: Option<String>,
        /// Delete snapshot NAME instead.
        #[arg(long, value_name = "NAME", conflicts_with = "name")]
        delete: Option<String>,
        /// Do not ask before deleting.
        #[arg(long, requires = "delete")]
        yes: bool,
    },
    /// List a VM's snapshots.
    Snaps { vm: String },
    /// Go back to a snapshot (default: the newest). A RAM snapshot brings
    /// the running guest back; a disk-only one needs the VM stopped.
    Restore { vm: String, name: Option<String> },
    /// Let agents (MCP) control a VM, or stop them.
    Agent {
        vm: String,
        #[arg(value_enum)]
        state: OnOff,
    },
    /// Change VM settings; they apply from the VM's next start.
    #[command(group(clap::ArgGroup::new("change").required(true).multiple(true)))]
    Set {
        vm: String,
        /// A VNC server on a Unix socket for humans (never TCP); reach it
        /// with `ssh -L 5901:<socket> <host>`.
        #[arg(long, value_enum, group = "change")]
        vnc: Option<OnOff>,
        /// vCPUs (the VM must be stopped).
        #[arg(long, group = "change")]
        cpus: Option<u32>,
        /// Memory, e.g. 4G or 1536M (the VM must be stopped).
        #[arg(long, value_parser = parse_mib, group = "change")]
        mem: Option<u64>,
    },
    /// Continue a paused VM (for example after the disk watchdog paused it).
    Resume { vm: String },
    /// Show host resources and what VMs use.
    Host,
    /// Delete a stopped VM and all its files.
    Rm {
        vm: String,
        /// Do not ask.
        #[arg(long)]
        yes: bool,
    },
    /// Serve the agent tools over MCP on stdin/stdout, or register them
    /// with Claude Code (`stallo mcp install`).
    #[command(args_conflicts_with_subcommands = true)]
    Mcp {
        #[command(subcommand)]
        action: Option<McpCmd>,
        /// Serve over streamable HTTP on IP:PORT instead of stdio. Only
        /// loopback or a Tailscale address; needs --token-file.
        #[arg(long, value_name = "IP:PORT", value_parser = stallo::mcp_http::parse_addr, requires = "token_file")]
        http: Option<std::net::SocketAddr>,
        /// File with the bearer token for --http (mode 0600, at least 32
        /// characters), e.g. from `head -c 32 /dev/urandom | base64`.
        #[arg(long, value_name = "FILE", requires = "http")]
        token_file: Option<PathBuf>,
    },
    /// List images, download one or delete one.
    Images {
        #[command(subcommand)]
        action: Option<ImagesCmd>,
    },
}

#[derive(Subcommand)]
enum McpCmd {
    /// Add `stallo mcp` to Claude Code's user config (`claude mcp add`), or
    /// print the JSON for other MCP clients if `claude` is not installed.
    Install,
}

#[derive(Subcommand)]
enum ImagesCmd {
    /// Download and verify an image.
    Pull { id: String },
    /// Delete a cached image (refused while a VM uses it). To get a newer
    /// build of a moving image, delete it and pull it again.
    Rm {
        id: String,
        /// Do not ask.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum OnOff {
    On,
    Off,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum Net {
    Offline,
    Internet,
}

/// Exit code for errors of stallo itself (daemon unreachable, no such VM,
/// timeout...), so they differ from a guest command's own exit code.
const STALLO_ERROR: u8 = 125;

fn main() -> ExitCode {
    let cli = Cli::parse();
    // stdout is the MCP channel for `stallo mcp`: errors go to stderr.
    let json = cli.json && !matches!(cli.command, Cmd::Mcp { action: None, .. });
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => return fail(&e.into(), json),
    };
    match rt.block_on(run(cli)) {
        Ok(code) => code,
        Err(e) => fail(&e, json),
    }
}

fn fail(e: &anyhow::Error, json: bool) -> ExitCode {
    if json {
        println!(
            "{}",
            serde_json::json!({"ok": false, "error": format!("{e:#}")})
        );
    } else {
        eprintln!("stallo: {e:#}");
    }
    ExitCode::from(STALLO_ERROR)
}

async fn run(cli: Cli) -> Result<ExitCode> {
    let explicit_socket = cli
        .socket
        .or_else(|| std::env::var_os("STALLO_SOCKET").map(PathBuf::from));
    let socket = match explicit_socket.clone() {
        Some(s) => s,
        None => stallo::paths::default_socket()?,
    };
    let call = |request: Request| {
        let socket = socket.clone();
        async move {
            api::call(
                &socket,
                &Envelope {
                    via: Via::Cli,
                    request,
                },
            )
            .await
        }
    };
    let json = cli.json;
    let print_json = |v: &Value| println!("{}", serde_json::to_string_pretty(v).unwrap());

    let is_run = matches!(cli.command, Cmd::Run { .. });
    match cli.command {
        Cmd::New {
            name,
            image,
            cpus,
            mem,
            disk,
            net,
            forwards,
            bind,
            no_wait,
            vnc,
        } => {
            let net = match net {
                Net::Offline => NetProfile::Offline,
                Net::Internet => NetProfile::Internet,
            };
            let forwards = forwards
                .iter()
                .map(|f| stallo::net::parse_forward(f, bind))
                .collect::<Result<_>>()?;
            let v = call(Request::New {
                name,
                image,
                vcpus: cpus,
                memory_mib: mem,
                disk_gib: disk,
                net,
                forwards,
                wait: !no_wait,
                vnc,
            })
            .await?;
            if json {
                print_json(&v);
            } else {
                let r: NewResult = serde_json::from_value(v)?;
                let when = match r.ready_ms {
                    Some(ms) => format!("ready in {:.0}s", ms as f64 / 1000.0),
                    None => "started".to_owned(),
                };
                println!("{}  {when}  {}", r.vm.name, summary(&r.vm));
            }
        }
        Cmd::Ls => {
            let v = call(Request::List).await?;
            if json {
                print_json(&v);
            } else {
                let vms: Vec<VmInfo> = serde_json::from_value(v)?;
                print_table(&vms);
            }
        }
        Cmd::Start { vm, no_wait } => {
            let v = call(Request::Start {
                name: vm.clone(),
                wait: !no_wait,
            })
            .await?;
            if json {
                print_json(&v);
            } else {
                println!("{vm}  started");
            }
        }
        Cmd::Stop { vm, force } => {
            call(Request::Stop {
                name: vm.clone(),
                force,
            })
            .await?;
            if !json {
                println!("{vm}  stopped");
            }
        }
        Cmd::Exec {
            vm,
            admin,
            timeout,
            argv,
        }
        | Cmd::Run {
            vm,
            admin,
            timeout,
            argv,
        } => {
            let request = if is_run {
                Request::Run {
                    name: vm,
                    argv,
                    admin,
                    timeout_s: timeout,
                }
            } else {
                Request::Exec {
                    name: vm,
                    argv,
                    admin,
                    timeout_s: timeout,
                    stdin: None,
                }
            };
            let v = call(request).await?;
            let r: ExecResult = serde_json::from_value(v.clone())?;
            if json {
                print_json(&v);
            } else {
                std::io::stdout().write_all(r.stdout.as_bytes())?;
                std::io::stderr().write_all(r.stderr.as_bytes())?;
                if r.truncated {
                    eprintln!("stallo: output truncated");
                }
            }
            return Ok(ExitCode::from(u8::try_from(r.exit_code).unwrap_or(255)));
        }
        Cmd::Cp { src, dst, admin } => {
            let bytes = match (guest_path(&src), guest_path(&dst)) {
                (None, Some((vm, path))) => upload(&call, &src, vm, path, admin).await?,
                (Some((vm, path)), None) => download(&call, vm, path, &dst, admin).await?,
                _ => bail!("copy between the host and a VM: one side must be <vm>:/path"),
            };
            if json {
                print_json(&serde_json::json!({"bytes": bytes}));
            } else {
                println!("copied {bytes} bytes");
            }
        }
        Cmd::Snap {
            vm,
            delete: Some(tag),
            yes,
            ..
        } => {
            if !yes {
                confirm(&format!("Delete snapshot {tag} of {vm}?"))?;
            }
            call(Request::SnapshotDelete {
                name: vm.clone(),
                tag: tag.clone(),
            })
            .await?;
            if !json {
                println!("{vm}  snapshot {tag} deleted");
            }
        }
        Cmd::Snap { vm, name, .. } => {
            let v = call(Request::Snapshot {
                name: vm.clone(),
                tag: name,
            })
            .await?;
            if json {
                print_json(&v);
            } else {
                let t: Taken = serde_json::from_value(v)?;
                println!("{vm}  {}", taken_line(&t));
            }
        }
        Cmd::Snaps { vm } => {
            let v = call(Request::Snapshots { name: vm }).await?;
            if json {
                print_json(&v);
            } else {
                let list: Vec<Snapshot> = serde_json::from_value(v)?;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs();
                print!("{}", snaps_table(&list, now));
            }
        }
        Cmd::Restore { vm, name } => {
            let v = call(Request::Restore {
                name: vm.clone(),
                tag: name,
            })
            .await?;
            if json {
                print_json(&v);
            } else {
                let r: Restored = serde_json::from_value(v)?;
                println!("{vm}  {}", restored_line(&r));
            }
        }
        Cmd::Set { vm, vnc, cpus, mem } => {
            // First, so a running VM is refused before VNC changes.
            if cpus.is_some() || mem.is_some() {
                let v = call(Request::SetResources {
                    name: vm.clone(),
                    vcpus: cpus,
                    memory_mib: mem,
                })
                .await?;
                if json {
                    print_json(&v);
                } else {
                    let info: VmInfo = serde_json::from_value(v)?;
                    println!("{vm}  {}", summary(&info));
                }
            }
            if let Some(vnc) = vnc {
                let on = matches!(vnc, OnOff::On);
                let v = call(Request::SetVnc {
                    name: vm.clone(),
                    on,
                })
                .await?;
                if json {
                    print_json(&v);
                } else {
                    let when = if v["running"] == true {
                        " from the next start"
                    } else {
                        ""
                    };
                    println!("{vm}  vnc {}{when}", if on { "on" } else { "off" });
                    if let Some(sock) = v["socket"].as_str() {
                        println!("socket: {sock}");
                    }
                }
            }
        }
        Cmd::Agent { vm, state } => {
            let on = matches!(state, OnOff::On);
            call(Request::SetAgent {
                name: vm.clone(),
                on,
            })
            .await?;
            if !json {
                if on {
                    println!("{vm}  agent control on");
                } else {
                    println!("{vm}  agent control off (agent calls already running finish first)");
                }
            }
        }
        Cmd::Resume { vm } => {
            call(Request::Resume { name: vm.clone() }).await?;
            if !json {
                println!("{vm}  resumed");
            }
        }
        Cmd::Host => {
            let v = call(Request::Host).await?;
            if json {
                print_json(&v);
            } else {
                let h: HostInfo = serde_json::from_value(v)?;
                print!("{h}");
            }
        }
        Cmd::Rm { vm, yes } => {
            if !yes {
                confirm(&format!("Delete VM {vm} and all its files?"))?;
            }
            call(Request::Rm { name: vm.clone() }).await?;
            if !json {
                println!("{vm}  removed");
            }
        }
        Cmd::Mcp {
            action: None,
            http: Some(addr),
            token_file: Some(token),
        } => stallo::mcp_http::serve(socket, addr, &token).await?,
        Cmd::Mcp { action: None, .. } => stallo::mcp::serve_stdio(socket).await?,
        Cmd::Mcp {
            action: Some(McpCmd::Install),
            ..
        } => {
            let exe = std::env::current_exe()?;
            let path = std::env::var_os("PATH").unwrap_or_default();
            // Claude Code starts the server from a project directory.
            let socket = explicit_socket.map(std::path::absolute).transpose()?;
            print!("{}", mcp_install(&exe, socket.as_deref(), &path)?);
        }
        Cmd::Images { action } => {
            // Pull and rm answer null; show the catalog afterwards.
            match action {
                Some(ImagesCmd::Pull { id }) => {
                    call(Request::Pull { image: id }).await?;
                }
                Some(ImagesCmd::Rm { id, yes }) => {
                    if !yes {
                        confirm(&format!(
                            "Delete image {id}? A later VM needs it pulled again."
                        ))?;
                    }
                    call(Request::ImageRm { image: id }).await?;
                }
                None => {}
            }
            let v = call(Request::Images).await?;
            if json {
                print_json(&v);
            } else {
                let images: Vec<ImageInfo> = serde_json::from_value(v)?;
                print!("{}", images_table(&images));
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// The arguments `stallo mcp` needs: `[--socket <path>] mcp`.
fn mcp_args(socket: Option<&std::path::Path>) -> Vec<std::ffi::OsString> {
    let mut args = Vec::new();
    if let Some(s) = socket {
        args.extend(["--socket".into(), s.as_os_str().to_owned()]);
    }
    args.push("mcp".into());
    args
}

/// Registers `stallo mcp` with Claude Code for this user when `claude` is
/// on `path`; otherwise returns the JSON snippet for any MCP client.
fn mcp_install(
    exe: &std::path::Path,
    socket: Option<&std::path::Path>,
    path: &std::ffi::OsStr,
) -> Result<String> {
    use std::os::unix::fs::PermissionsExt;
    // Only absolute PATH entries: an empty or relative one would run a
    // `claude` from the current directory.
    let claude = std::env::split_paths(path)
        .filter(|d| d.is_absolute())
        .map(|d| d.join("claude"))
        .find(|c| {
            std::fs::metadata(c).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        });
    let Some(claude) = claude else {
        let args: Vec<String> = mcp_args(socket)
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let snippet = serde_json::json!({"mcpServers": {"stallo": {
            "command": exe, "args": args}}});
        return Ok(format!(
            "claude is not installed; add this to your MCP client's config:\n{}\n",
            serde_json::to_string_pretty(&snippet)?
        ));
    };
    let status = std::process::Command::new(&claude)
        .args(["mcp", "add", "--scope", "user", "stallo", "--"])
        .arg(exe)
        .args(mcp_args(socket))
        .status()
        .with_context(|| format!("cannot run {}", claude.display()))?;
    ensure!(status.success(), "claude mcp add failed ({status})");
    Ok("stallo is now an MCP server in Claude Code (user scope)\n".to_owned())
}

/// `vm:/abs/path` names a guest file; anything else is a host path.
fn guest_path(arg: &str) -> Option<(&str, &str)> {
    let (vm, path) = arg.split_once(':')?;
    (stallo::config::validate_name(vm).is_ok() && path.starts_with('/')).then_some((vm, path))
}

/// Largest file `stallo cp` copies from a guest, so a hostile guest
/// cannot fill the host disk with an endless file.
const MAX_DOWNLOAD: u64 = 16 << 30;

/// Copies a host file into the guest in appended chunks (requests are
/// capped at 1 MiB). Not atomic: the first chunk replaces the guest file,
/// so a failure midway leaves a partial file. A guest path ending in `/`
/// gets the host file's name.
async fn upload<F, Fut>(call: &F, src: &str, vm: &str, path: &str, admin: bool) -> Result<u64>
where
    F: Fn(Request) -> Fut,
    Fut: std::future::Future<Output = Result<Value>>,
{
    use base64::Engine;
    use std::io::Read;
    let mut path = path.to_owned();
    if path.ends_with('/') {
        let name = std::path::Path::new(src)
            .file_name()
            .and_then(|n| n.to_str())
            .context("the host path has no file name")?;
        path.push_str(name);
    }
    let mut file = std::fs::File::open(src).with_context(|| format!("cannot open {src}"))?;
    let mut chunk = Vec::with_capacity(api::FILE_WRITE_CHUNK);
    let mut total = 0u64;
    loop {
        chunk.clear();
        (&mut file)
            .take(api::FILE_WRITE_CHUNK as u64)
            .read_to_end(&mut chunk)?;
        // The first write also creates an empty file.
        if !chunk.is_empty() || total == 0 {
            call(Request::FileWrite {
                name: vm.to_owned(),
                path: path.clone(),
                data_base64: base64::engine::general_purpose::STANDARD.encode(&chunk),
                append: total > 0,
                admin,
            })
            .await?;
        }
        total += chunk.len() as u64;
        if chunk.len() < api::FILE_WRITE_CHUNK {
            return Ok(total);
        }
    }
}

/// Copies a guest file to the host in 8 MiB parts, into `<dst>.part` first
/// and renamed when complete, so a failure never clobbers `dst`. A
/// directory as `dst` gets the guest file's name.
async fn download<F, Fut>(call: &F, vm: &str, path: &str, dst: &str, admin: bool) -> Result<u64>
where
    F: Fn(Request) -> Fut,
    Fut: std::future::Future<Output = Result<Value>>,
{
    let mut target = PathBuf::from(dst);
    if target.is_dir() {
        let name = std::path::Path::new(path)
            .file_name()
            .context("the guest path has no file name")?;
        target.push(name);
    }
    let mut part = target.clone().into_os_string();
    part.push(".part");
    let part = PathBuf::from(part);
    let result = download_to(call, vm, path, &part, admin).await;
    match result {
        Ok(n) => {
            std::fs::rename(&part, &target)
                .with_context(|| format!("cannot write {}", target.display()))?;
            Ok(n)
        }
        Err(e) => {
            let _ = std::fs::remove_file(&part);
            Err(e)
        }
    }
}

async fn download_to<F, Fut>(
    call: &F,
    vm: &str,
    path: &str,
    part: &std::path::Path,
    admin: bool,
) -> Result<u64>
where
    F: Fn(Request) -> Fut,
    Fut: std::future::Future<Output = Result<Value>>,
{
    use base64::Engine;
    let mut out = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(part)
        .with_context(|| format!("cannot create {}", part.display()))?;
    let mut offset = 0u64;
    loop {
        let v = call(Request::FileRead {
            name: vm.to_owned(),
            path: path.to_owned(),
            offset,
            max_bytes: Some(8 << 20),
            admin,
        })
        .await?;
        let chunk: api::FileData = serde_json::from_value(v)?;
        let data = base64::engine::general_purpose::STANDARD.decode(&chunk.data_base64)?;
        // A guest that claims more but sends nothing would loop forever.
        ensure!(
            !chunk.more || !data.is_empty(),
            "the guest sent no data for {path}"
        );
        offset += data.len() as u64;
        ensure!(
            offset <= MAX_DOWNLOAD,
            "{path} is larger than {} GiB; not copied",
            MAX_DOWNLOAD >> 30
        );
        out.write_all(&data)?;
        if !chunk.more {
            return Ok(offset);
        }
    }
}

/// `2 vCPU · 2 GiB · offline`, plus port forwards such as
/// ` · 127.0.0.1:8080→80`.
fn summary(vm: &VmInfo) -> String {
    let mut s = format!(
        "{} vCPU · {} · {}",
        vm.vcpus,
        mib(vm.memory_mib),
        serde_json::to_value(vm.net)
            .unwrap()
            .as_str()
            .unwrap_or("?")
    );
    for f in &vm.forwards {
        let host = std::net::SocketAddr::new(f.bind, f.host);
        s.push_str(&format!(" · {host}→{}", f.guest));
    }
    s
}

fn mib(m: u64) -> String {
    if m.is_multiple_of(1024) {
        format!("{} GiB", m / 1024)
    } else {
        format!("{m} MiB")
    }
}

fn secs(ms: u64) -> String {
    format!("{:.1} s", ms as f64 / 1000.0)
}

/// `snapshot s1 taken (RAM, guest paused 2.2 s)`.
fn taken_line(t: &Taken) -> String {
    let what = match (t.ram, t.pause_ms) {
        (true, Some(p)) => format!("RAM, guest paused {}", secs(p)),
        (true, None) => "RAM".to_owned(),
        (false, _) => "disk only; the VM is stopped".to_owned(),
    };
    format!("snapshot {} taken ({what})", t.name)
}

/// `restored s1, running (guest agent back after 0.1 s)`.
fn restored_line(r: &Restored) -> String {
    let agent = match r.agent_ms {
        Some(ms) => format!(" (guest agent back after {})", secs(ms)),
        None if r.state == "running" => " (guest agent not answering yet)".to_owned(),
        None => String::new(),
    };
    format!("restored {}, {}{agent}", r.name, r.state)
}

/// How long ago, roughly: `42 s`, `5 min`, `3 h`, `2 d`.
fn ago(secs: u64) -> String {
    match secs {
        0..60 => format!("{secs} s"),
        60..3600 => format!("{} min", secs / 60),
        3600..86400 => format!("{} h", secs / 3600),
        _ => format!("{} d", secs / 86400),
    }
}

fn snaps_table(list: &[Snapshot], now: u64) -> String {
    use std::fmt::Write;
    if list.is_empty() {
        return "no snapshots; take one with `stallo snap <vm>`\n".to_owned();
    }
    let w = list.iter().map(|s| s.name.len()).max().unwrap_or(0).max(24);
    let mut out = format!(
        "{:<w$} {:>10} {:>9} {:>9}\n",
        "NAME", "TAKEN", "RAM", "UPTIME"
    );
    for s in list {
        let (ram, up) = if s.ram_bytes > 0 {
            (mib(s.ram_bytes >> 20), ago(s.vm_clock_ms / 1000))
        } else {
            ("-".to_owned(), "-".to_owned())
        };
        let taken = format!("{} ago", ago(now.saturating_sub(s.created)));
        let _ = writeln!(out, "{:<w$} {taken:>10} {ram:>9} {up:>9}", s.name);
    }
    out
}

fn images_table(images: &[ImageInfo]) -> String {
    let mut s = format!(
        "{:<16} {:<14} {:>9}  {:<12} NOTES\n",
        "ID", "STATE", "SIZE", "TRUST"
    );
    for i in images {
        let state = if i.cached { "cached" } else { "not downloaded" };
        let size = i.size_bytes.map_or("-".into(), |b| mib(b >> 20));
        let trust = serde_json::to_value(i.trust).unwrap_or_default();
        let signed = i.sig_date.as_ref().map(|d| format!("signed {d}"));
        let notes = std::iter::once(i.name.as_str())
            .chain(signed.as_deref())
            .chain(i.notes.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join("; ");
        s.push_str(&format!(
            "{:<16} {:<14} {:>9}  {:<12} {notes}\n",
            i.id,
            state,
            size,
            trust.as_str().unwrap_or("-")
        ));
    }
    s
}

fn print_table(vms: &[VmInfo]) {
    if vms.is_empty() {
        println!("no VMs; create one with `stallo new`");
        return;
    }
    println!(
        "{:<20} {:<12} {:>4} {:>9} {:>6}  {:<8} AGENT",
        "NAME", "STATE", "CPUS", "MEMORY", "DISK", "NET"
    );
    for vm in vms {
        println!(
            "{:<20} {:<12} {:>4} {:>9} {:>5}G  {:<8} {}",
            vm.name,
            vm.state,
            vm.vcpus,
            mib(vm.memory_mib),
            vm.disk_gib,
            serde_json::to_value(vm.net)
                .unwrap()
                .as_str()
                .unwrap_or("?"),
            if vm.agent_control { "on" } else { "off" }
        );
    }
}

/// Asks on a terminal; refuses without one (scripts must pass `--yes`).
fn confirm(question: &str) -> Result<()> {
    if !std::io::stdin().is_terminal() {
        bail!("refusing to delete without a terminal; pass --yes");
    }
    eprint!("{question} [y/N] ");
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    if !matches!(answer.trim(), "y" | "Y" | "yes") {
        bail!("cancelled");
    }
    Ok(())
}

/// Parses `2G`, `1536M`, `512MiB` or a plain MiB count.
fn parse_mib(s: &str) -> Result<u64> {
    let s = s.trim();
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: u64 = num.parse().with_context(|| format!("invalid size {s:?}"))?;
    let factor = match unit.to_ascii_lowercase().as_str() {
        "" | "m" | "mb" | "mib" => 1,
        "g" | "gb" | "gib" => 1024,
        _ => bail!("invalid size {s:?}; use e.g. 2G or 1536M"),
    };
    n.checked_mul(factor).context("size too large")
}

/// Parses `20G`, `20GiB` or a plain GiB count.
fn parse_gib(s: &str) -> Result<u64> {
    let s = s.trim();
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    ensure!(
        matches!(unit.to_ascii_lowercase().as_str(), "" | "g" | "gb" | "gib"),
        "invalid size {s:?}; use e.g. 20G"
    );
    num.parse()
        .with_context(|| format!("invalid size {s:?}; use e.g. 20G"))
}

#[cfg(test)]
mod tests {
    #[test]
    fn mcp_http_args() {
        use clap::Parser;
        let parse = |a: &[&str]| super::Cli::try_parse_from(a);
        assert!(
            parse(&[
                "stallo",
                "mcp",
                "--http",
                "127.0.0.1:8765",
                "--token-file",
                "/t"
            ])
            .is_ok()
        );
        assert!(parse(&["stallo", "mcp", "--http", "127.0.0.1:8765"]).is_err());
        assert!(parse(&["stallo", "mcp", "--token-file", "/t"]).is_err());
        assert!(
            parse(&[
                "stallo",
                "mcp",
                "--http",
                "localhost:8765",
                "--token-file",
                "/t"
            ])
            .is_err()
        );
        assert!(
            parse(&[
                "stallo",
                "mcp",
                "--http",
                "127.0.0.1:8765",
                "--token-file",
                "/t",
                "install"
            ])
            .is_err()
        );
    }

    use super::*;

    #[test]
    fn snapshot_output() {
        let snap = |name: &str, ram_bytes, created, vm_clock_ms| Snapshot {
            name: name.into(),
            ram_bytes,
            created,
            vm_clock_ms,
        };
        let list = [
            snap("before-upgrade", 412 << 20, 1000, 754_000),
            snap("disk", 0, 9000, 0),
        ];
        assert_eq!(
            snaps_table(&list, 10_000),
            "NAME                          TAKEN       RAM    UPTIME\n\
             before-upgrade              2 h ago   412 MiB    12 min\n\
             disk                     16 min ago         -         -\n"
        );
        assert!(snaps_table(&[], 0).starts_with("no snapshots"));
        assert_eq!(ago(59), "59 s");
        assert_eq!(ago(86_400 * 3), "3 d");
        let t = Taken {
            name: "s1".into(),
            ram: true,
            pause_ms: Some(2210),
            ms: 2220,
        };
        assert_eq!(
            taken_line(&t),
            "snapshot s1 taken (RAM, guest paused 2.2 s)"
        );
        let t = Taken {
            ram: false,
            pause_ms: None,
            ..t
        };
        assert_eq!(
            taken_line(&t),
            "snapshot s1 taken (disk only; the VM is stopped)"
        );
        let r = Restored {
            name: "s1".into(),
            state: "running".into(),
            pause_ms: Some(2500),
            ms: 2600,
            agent_ms: Some(120),
        };
        assert_eq!(
            restored_line(&r),
            "restored s1, running (guest agent back after 0.1 s)"
        );
        let r = Restored {
            state: "stopped".into(),
            agent_ms: None,
            ..r
        };
        assert_eq!(restored_line(&r), "restored s1, stopped");
    }

    #[test]
    fn sizes() {
        assert_eq!(parse_mib("2G").unwrap(), 2048);
        assert_eq!(parse_mib("1536M").unwrap(), 1536);
        assert_eq!(parse_mib("512MiB").unwrap(), 512);
        assert_eq!(parse_mib("4gib").unwrap(), 4096);
        assert_eq!(parse_mib("300").unwrap(), 300);
        assert!(parse_mib("2T").is_err());
        assert!(parse_mib("G").is_err());
        assert!(parse_mib("-1G").is_err());
        assert_eq!(parse_gib("20G").unwrap(), 20);
        assert_eq!(parse_gib("20").unwrap(), 20);
        assert!(parse_gib("20M").is_err());
        assert!(parse_gib("20bib").is_err());
        assert!(parse_gib("20B").is_err());
        assert_eq!(parse_gib("20GiB").unwrap(), 20);
    }

    #[test]
    fn images_columns() {
        let v = serde_json::json!([{"id": "ubuntu-26.04", "name": "Ubuntu", "cached": false,
            "os": "linux", "trust": "signed-sums", "size_bytes": 865115136,
            "sig_date": "2026-09-29", "notes": ["guest-agent packages not downloaded yet"]}]);
        let images: Vec<ImageInfo> = serde_json::from_value(v).unwrap();
        assert_eq!(
            images_table(&images),
            "ID               STATE               SIZE  TRUST        NOTES\n\
             ubuntu-26.04     not downloaded   825 MiB  signed-sums  Ubuntu; signed 2026-09-29; guest-agent packages not downloaded yet\n"
        );
        // What an older stallod sends.
        let old = serde_json::json!([{"id": "ubuntu-26.04", "name": "Ubuntu", "cached": true}]);
        let images: Vec<ImageInfo> = serde_json::from_value(old).unwrap();
        let table = images_table(&images);
        assert_eq!(
            table.lines().nth(1),
            Some("ubuntu-26.04     cached                 -  -            Ubuntu")
        );
    }

    /// A fake daemon holding one guest file.
    fn fake_guest(
        file: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
        part: usize,
        lie: bool,
    ) -> impl Fn(Request) -> std::future::Ready<Result<Value>> {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;
        move |r| {
            let mut f = file.lock().unwrap();
            std::future::ready(match r {
                Request::FileWrite {
                    data_base64,
                    append,
                    path,
                    ..
                } => {
                    assert!(!path.ends_with('/'));
                    if !append {
                        f.clear();
                    }
                    f.extend(b64.decode(data_base64).unwrap());
                    Ok(Value::Null)
                }
                Request::FileRead { path, offset, .. } if path == "/f" => {
                    let start = (offset as usize).min(f.len());
                    let end = (start + part).min(f.len());
                    let data = if lie { &[][..] } else { &f[start..end] };
                    Ok(serde_json::json!({"data_base64": b64.encode(data),
                        "size": data.len(), "more": lie || end < f.len()}))
                }
                _ => Err(anyhow::anyhow!("no such file")),
            })
        }
    }

    #[tokio::test]
    async fn copies_both_ways() {
        let dir = tempfile::tempdir().unwrap();
        let guest = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let call = fake_guest(guest.clone(), 1000, false);
        let src = dir.path().join("src");
        for len in [0, 1, api::FILE_WRITE_CHUNK, 2 * api::FILE_WRITE_CHUNK + 7] {
            let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
            std::fs::write(&src, &data).unwrap();
            let n = upload(&call, src.to_str().unwrap(), "dev", "/f", false)
                .await
                .unwrap();
            assert_eq!(n as usize, len);
            assert_eq!(*guest.lock().unwrap(), data);
            // Down again in 1000-byte parts, into a directory.
            let back = dir.path().join("back");
            std::fs::create_dir_all(&back).unwrap();
            download(&call, "dev", "/f", back.to_str().unwrap(), false)
                .await
                .unwrap();
            assert_eq!(std::fs::read(back.join("f")).unwrap(), data);
        }
    }

    #[tokio::test]
    async fn download_failures_leave_the_target_alone() {
        let dir = tempfile::tempdir().unwrap();
        let keep = dir.path().join("keep");
        std::fs::write(&keep, b"precious").unwrap();
        let guest = std::sync::Arc::new(std::sync::Mutex::new(b"data".to_vec()));
        let call = fake_guest(guest.clone(), 1000, false);
        assert!(
            download(&call, "dev", "/missing", keep.to_str().unwrap(), false)
                .await
                .is_err()
        );
        // A guest that says "more" but sends nothing.
        let liar = fake_guest(guest, 1000, true);
        let err = download(&liar, "dev", "/f", keep.to_str().unwrap(), false)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no data"), "{err}");
        assert_eq!(std::fs::read(&keep).unwrap(), b"precious");
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            1,
            "no .part left"
        );
    }

    /// Uses a fake `claude` in a temporary PATH: the real Claude Code
    /// config is never touched.
    #[test]
    fn mcp_install_uses_claude_or_prints_json() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let exe = std::path::Path::new("/opt/stallo/bin/stallo");

        let out = mcp_install(exe, None, bin.as_os_str()).unwrap();
        assert!(out.contains("not installed"), "{out}");
        let json = &out[out.find('{').unwrap()..];
        let v: Value = serde_json::from_str(json).unwrap();
        assert_eq!(
            v["mcpServers"]["stallo"]["command"],
            "/opt/stallo/bin/stallo"
        );
        assert_eq!(
            v["mcpServers"]["stallo"]["args"],
            serde_json::json!(["mcp"])
        );

        let log = dir.path().join("args");
        let fake = bin.join("claude");
        std::fs::write(
            &fake,
            format!("#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\n", log.display()),
        )
        .unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let sock = std::path::Path::new("/run/x/api.sock");
        // A script just written can be "busy" if another test thread forked
        // meanwhile (ETXTBSY): retry.
        let run = |sock| {
            for _ in 0..20 {
                match mcp_install(exe, sock, bin.as_os_str()) {
                    Err(e) if format!("{e:#}").contains("busy") => {
                        std::thread::sleep(std::time::Duration::from_millis(50))
                    }
                    r => return r,
                }
            }
            panic!("text file stays busy")
        };
        run(Some(sock)).unwrap();
        let args = std::fs::read_to_string(&log).unwrap();
        assert_eq!(
            args.lines().collect::<Vec<_>>(),
            [
                "mcp",
                "add",
                "--scope",
                "user",
                "stallo",
                "--",
                "/opt/stallo/bin/stallo",
                "--socket",
                "/run/x/api.sock",
                "mcp"
            ]
        );

        std::fs::write(&fake, "#!/bin/sh\nexit 3\n").unwrap();
        assert!(run(None).is_err());

        // A relative PATH entry is never searched; a non-executable file is
        // not a program.
        let out = mcp_install(exe, None, std::ffi::OsStr::new("bin:.")).unwrap();
        assert!(out.contains("not installed"));
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            mcp_install(exe, None, bin.as_os_str())
                .unwrap()
                .contains("not installed")
        );
    }

    #[test]
    fn guest_paths() {
        assert_eq!(guest_path("dev:/tmp/a"), Some(("dev", "/tmp/a")));
        assert_eq!(guest_path("dev:/a:b"), Some(("dev", "/a:b")));
        for host in ["./a", "/tmp/dev:/x", "dev:relative", "Dev:/x", "a"] {
            assert_eq!(guest_path(host), None, "{host}");
        }
    }

    #[test]
    fn cli_parses() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
        let c = Cli::try_parse_from(["stallo", "exec", "dev", "--", "uname", "-a"]).unwrap();
        assert!(matches!(c.command, Cmd::Exec { ref argv, .. } if argv == &["uname", "-a"]));
        let set = |a: &[&str]| Cli::try_parse_from([&["stallo", "set", "dev"], a].concat());
        let c = set(&["--cpus", "4", "--mem", "4G"]).unwrap();
        assert!(matches!(
            c.command,
            Cmd::Set {
                vnc: None,
                cpus: Some(4),
                mem: Some(4096),
                ..
            }
        ));
        let c = set(&["--vnc", "on"]).unwrap();
        assert!(matches!(
            c.command,
            Cmd::Set {
                vnc: Some(OnOff::On),
                cpus: None,
                mem: None,
                ..
            }
        ));
        assert!(set(&["--mem", "1G", "--vnc", "off"]).is_ok());
        assert!(set(&[]).is_err(), "at least one setting");
        assert!(set(&["--mem", "2T"]).is_err());
        let c = Cli::try_parse_from(["stallo", "new", "dev", "--vnc"]).unwrap();
        assert!(matches!(c.command, Cmd::New { vnc: true, .. }));
        let c = Cli::try_parse_from(["stallo", "new", "dev"]).unwrap();
        assert!(matches!(c.command, Cmd::New { vnc: false, .. }));
    }
}
