//! stallod: the Stallo daemon. It owns every VM and serves the API socket.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use clap::Parser;
use tokio::io::{AsyncRead, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::Semaphore;

use std::time::Instant;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde_json::{Value, json};
use stallo::api::Via;
use stallo::api::{self, Envelope, ExecResult, ImageInfo, NewResult, Request, Response, VmInfo};
use stallo::audit;
use stallo::cgroup::Cgroups;
use stallo::config::{DaemonConfig, Mode, VmConfig, validate_name};
use stallo::images;
use stallo::paths::{Paths, safe_remove};
use stallo::read_line;
use stallo::vm::{
    Button, EXEC_DEFAULT_TIMEOUT, Manager, NewVm, READY_TIMEOUT, SCREEN_DEFAULT_STABLE,
    SCREEN_DEFAULT_TIMEOUT, Screenshot,
};
use tokio::net::unix::UCred;

/// Most API connections served at once.
const MAX_CONNECTIONS: usize = 64;
/// How long a shutdown waits for the VMs to power off before killing them.
const STOP_ALL_TIMEOUT: Duration = Duration::from_secs(80);

#[derive(Parser)]
#[command(version, about = "Stallo daemon: owns VMs, serves the stallo API")]
struct Args {
    /// Dev mode: run as the current user with data under $HOME, offline VMs
    /// only. Without it: production mode, as the `stallo` user with data in
    /// /var/lib/stallo and runtime files in /run/stallo.
    #[arg(long)]
    dev: bool,
    /// Override the data directory (dev mode only).
    #[arg(long, requires = "dev")]
    data_dir: Option<PathBuf>,
    /// Override the runtime directory (dev mode only).
    #[arg(long, requires = "dev")]
    runtime_dir: Option<PathBuf>,
}

fn main() -> Result<()> {
    // STALLO_LOG=debug|info|warn|error (default info).
    let level = std::env::var("STALLO_LOG")
        .ok()
        .and_then(|l| l.parse().ok())
        .unwrap_or(tracing::Level::INFO);
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(std::io::stderr)
        .init();
    let args = Args::parse();
    let mode = if args.dev {
        Mode::Dev
    } else {
        Mode::Production
    };
    if mode == Mode::Production {
        // The host's network table and every file permission assume the
        // dedicated `stallo` user.
        ensure!(
            !rustix::process::getuid().is_root(),
            "stallod must not run as root; run it as the stallo user"
        );
    }
    // New files are private to the daemon user (and its group in production).
    rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o027));

    let paths = match mode {
        Mode::Dev => {
            let defaults = Paths::dev()?;
            Paths::new(
                args.data_dir.unwrap_or(defaults.data),
                args.runtime_dir.unwrap_or(defaults.runtime),
            )?
        }
        Mode::Production => Paths::production()?,
    }
    .prepare()?;
    // One daemon per runtime dir: a second one would wipe the first one's
    // sockets. Held (open) for the daemon's lifetime.
    let lock = std::fs::File::create(paths.runtime.join("stallod.lock"))?;
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .context("another stallod is already running for this runtime directory")?;
    let config = DaemonConfig::load(&paths.config_file())?;
    // Before any thread or child exists: move into the delegated cgroup
    // leaf. Without working limits the daemon does not start.
    let cgroups = Cgroups::setup()?;

    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?
        .block_on(serve(paths, config, cgroups, mode))?;
    drop(lock);
    Ok(())
}

async fn serve(paths: Paths, config: DaemonConfig, cgroups: Cgroups, mode: Mode) -> Result<()> {
    let manager = Manager::new(paths.clone(), config, cgroups, mode);
    manager.cleanup_leftovers().await?;
    if let Err(e) = stallo::images::sweep_imports(&paths) {
        tracing::error!("cannot remove what cut-off imports left: {e:#}");
    }

    let sock = paths.api_socket();
    safe_remove(&paths.runtime, &sock)?;
    let listener = UnixListener::bind(&sock).context("cannot bind the API socket")?;
    // Dev: the owner only. Production: the daemon's group too (S2); its
    // members also need to traverse the runtime dir, but not the per-VM
    // dirs below it (0700).
    let (sock_mode, dir_mode) = match mode {
        Mode::Dev => (0o600, 0o700),
        Mode::Production => (0o660, 0o750),
    };
    std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(sock_mode))?;
    std::fs::set_permissions(&paths.runtime, std::fs::Permissions::from_mode(dir_mode))?;
    tracing::info!("listening on {}", sock.display());
    tokio::spawn(stallo::host::watchdog(manager.clone()));
    if mode == Mode::Production {
        tokio::spawn(stallo::net::watchdog(manager.clone()));
    }

    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let own_uid = rustix::process::getuid().as_raw();
    // Production: members of the daemon's group may use the API too; the
    // socket and the runtime dir are group-accessible (S2).
    let group = (mode == Mode::Production).then(|| rustix::process::getgid().as_raw());
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(a) => a,
                    Err(e) => {
                        // E.g. out of file descriptors: do not spin.
                        tracing::warn!("accept failed: {e}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let Ok(permit) = slots.clone().try_acquire_owned() else {
                    tracing::warn!("too many connections; refusing one");
                    let _ = stream.try_write(b"{\"ok\":false,\"error\":\"stallod is busy; try again\"}\n");
                    continue;
                };
                let manager = manager.clone();
                tokio::spawn(async move {
                    if let Err(e) = connection(&manager, stream, own_uid, group).await {
                        tracing::debug!("connection: {e:#}");
                    }
                    drop(permit);
                });
            }
            _ = term.recv() => break,
            _ = int.recv() => break,
        }
    }
    tracing::info!("shutting down: stopping all VMs");
    drop(listener);
    let _ = safe_remove(&paths.runtime, &sock);
    // Let requests in flight finish (bounded), so no VM starts after the
    // list of VMs to stop is taken. Anything still running when the daemon
    // exits is killed with its cgroup by systemd.
    let drained = tokio::time::timeout(
        Duration::from_secs(30),
        slots.acquire_many(MAX_CONNECTIONS as u32),
    )
    .await;
    if drained.is_err() {
        tracing::warn!("requests still running after 30 s; stopping VMs anyway");
    }
    // Within systemd's TimeoutStopSec=120 (30 s above + 80 s): a VM whose
    // lifecycle lock is held (snapshot job, `stallo run`) is killed here
    // rather than by systemd at the timeout.
    if tokio::time::timeout(STOP_ALL_TIMEOUT, manager.stop_all())
        .await
        .is_err()
    {
        tracing::warn!("VMs still running after {STOP_ALL_TIMEOUT:?}; killing them");
    }
    manager.kill_all();
    Ok(())
}

async fn connection(
    manager: &Arc<Manager>,
    stream: UnixStream,
    own_uid: u32,
    group: Option<u32>,
) -> Result<()> {
    let cred = stream.peer_cred()?;
    let mut gids = vec![cred.gid()];
    if group.is_some() {
        gids.extend(api::peer_groups(&stream)?);
    }
    if !api::authorize(cred.uid(), &gids, own_uid, group) {
        tracing::warn!("refused API peer uid {} pid {:?}", cred.uid(), cred.pid());
        return Ok(());
    }
    let (r, mut w) = stream.into_split();
    let mut r = BufReader::new(r);
    let mut line = Vec::new();
    let got = tokio::time::timeout(
        api::REQUEST_TIMEOUT,
        read_line(&mut r, &mut line, api::MAX_REQUEST),
    )
    .await
    .context("request timed out")??;
    if !got {
        return Ok(());
    }
    // What follows the request line: an import's body, and otherwise
    // nothing (see `dispatch`).
    let (response, audit) = match serde_json::from_slice::<Envelope>(&line) {
        Ok(env) => handle(manager, env, &cred, r).await,
        Err(e) => {
            tracing::info!(
                "invalid request from uid {} pid {:?}",
                cred.uid(),
                cred.pid()
            );
            let e = anyhow::anyhow!("invalid request: {e}");
            (Response::err(&e), None)
        }
    };
    let mut ok = response.ok;
    let mut out = serde_json::to_vec(&response).unwrap_or_default();
    drop(response);
    if out.is_empty() || out.len() > api::MAX_RESPONSE {
        ok = false;
        out = serde_json::to_vec(&Response::err(&anyhow::anyhow!("response too large")))?;
    }
    if let Some((mut file, mut entry)) = audit {
        entry.result_bytes = out.len() as u64;
        entry.ok = ok;
        let written = tokio::task::spawn_blocking(move || audit::write(&mut file, &entry)).await;
        if !matches!(written, Ok(Ok(()))) {
            tracing::error!("cannot write the audit log: {written:?}");
        }
    }
    out.push(b'\n');
    tokio::time::timeout(Duration::from_secs(30), w.write_all(&out))
        .await
        .context("response write timed out")??;
    Ok(())
}

/// Runs one API request and logs it (operation, caller, result, duration;
/// never arguments). Returns the response and the open audit log with the
/// entry to write (the caller adds the response size). An agent call that
/// cannot be audited is refused. `client` is the rest of the client's
/// stream.
async fn handle(
    m: &Arc<Manager>,
    env: Envelope,
    peer: &UCred,
    client: impl AsyncRead + Unpin,
) -> (Response, Option<(std::fs::File, audit::Entry)>) {
    let started = Instant::now();
    let (op, vm, args, argv0) = audit::describe(&env.request);
    let image = audit::image(&env.request);
    let log = vm
        .filter(|n| validate_name(n).is_ok() && m.paths.vm_dir(n).is_dir())
        .unwrap_or(audit::DAEMON)
        .to_owned();
    let dir = m.paths.audit_dir();
    let file = tokio::task::spawn_blocking(move || audit::open(&dir, &log))
        .await
        .map_err(anyhow::Error::from)
        .and_then(|r| Ok(r?));
    let result = match (&file, env.via) {
        (Err(e), Via::Mcp) => Err(anyhow::anyhow!(
            "the audit log cannot be written ({e:#}); agent calls are refused"
        )),
        _ => match api::check_agent(env.via, &env.request, m.config.agents_can_create, |n| {
            Ok(m.load(n)?.agent_control)
        }) {
            Ok(()) => dispatch(m, env.via, env.request, client).await,
            Err(e) => Err(e),
        },
    };
    let ms = started.elapsed().as_millis() as u64;
    tracing::info!(
        "{op} via {:?} from uid {} pid {:?}: {} in {ms} ms",
        env.via,
        peer.uid(),
        peer.pid(),
        if result.is_ok() { "ok" } else { "error" },
    );
    let file = match file {
        Ok(f) => Some(f),
        Err(e) => {
            tracing::error!("cannot open the audit log: {e:#}");
            None
        }
    };
    let audit = file.map(|f| {
        let entry = audit::Entry {
            time_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_millis() as u64),
            uid: peer.uid(),
            pid: peer.pid(),
            via: env.via,
            op,
            image,
            sha256: result.as_ref().ok().and_then(|v| audit::sha256(op, v)),
            args: args.into_iter().collect(),
            argv0,
            result_bytes: 0,
            ms,
            ok: result.is_ok(),
        };
        (f, entry)
    });
    let response = match result {
        Ok(data) => Response {
            ok: true,
            data,
            error: None,
        },
        Err(e) => Response::err(&e),
    };
    (response, audit)
}

async fn dispatch(
    m: &Arc<Manager>,
    via: Via,
    request: Request,
    mut client: impl AsyncRead + Unpin,
) -> Result<Value> {
    Ok(match request {
        Request::New {
            name,
            image,
            vcpus,
            memory_mib,
            disk_gib,
            net,
            forwards,
            wait,
            vnc,
        } => {
            let new = NewVm {
                name: name.clone(),
                image,
                vcpus,
                memory_mib,
                disk_gib,
                net,
                forwards,
                agent_control: via == Via::Mcp,
                // Pulls are for humans (Gate::Closed), also through `new`.
                may_pull: via == Via::Cli,
                // Agents never get here with vnc (Gate::Closed).
                vnc,
            };
            let wait = wait && images::has_agent(&new.image);
            let started = Instant::now();
            m.create(&new).await?;
            // `new` is all or nothing: a VM that never became ready is
            // stopped and removed again.
            let ready = match m.start(&name).await {
                Ok(_) if wait => m.wait_ready(&name, READY_TIMEOUT).await.map(drop),
                Ok(_) => Ok(()),
                Err(e) => Err(e),
            };
            if let Err(e) = ready {
                if m.running(&name).is_some()
                    && let Err(stop) = m.stop(&name, true).await
                {
                    tracing::error!("{name}: stop after failed new: {stop:#}");
                }
                if let Err(rm) = m.remove(&name).await {
                    tracing::error!("{name}: cleanup after failed new: {rm:#}");
                }
                return Err(e);
            }
            let ready_ms = wait.then(|| started.elapsed().as_millis() as u64);
            json!(NewResult {
                vm: info(m, &m.load(&name)?).await,
                ready_ms
            })
        }
        Request::List => {
            let mut vms = Vec::new();
            for cfg in m.list()? {
                vms.push(info(m, &cfg).await);
            }
            json!(vms)
        }
        Request::Start { name, wait } => {
            m.start(&name).await?;
            if wait && images::has_agent(&m.load(&name)?.image) {
                m.wait_ready(&name, READY_TIMEOUT).await?;
            }
            json!(info(m, &m.load(&name)?).await)
        }
        Request::Stop { name, force } => {
            m.stop(&name, force).await?;
            Value::Null
        }
        Request::Exec {
            name,
            argv,
            admin,
            timeout_s,
            stdin,
        } => {
            let limit = timeout_s.map_or(EXEC_DEFAULT_TIMEOUT, Duration::from_secs);
            let stdin = stdin.as_deref().map(str::as_bytes);
            let out = m.exec(&name, &argv, admin, limit, stdin).await?;
            json!(ExecResult {
                exit_code: out.exit_code,
                stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
                truncated: out.truncated,
            })
        }
        Request::Run {
            name,
            argv,
            admin,
            timeout_s,
        } => {
            let limit = timeout_s.map_or(EXEC_DEFAULT_TIMEOUT, Duration::from_secs);
            // The client sends nothing after its request: end of stream
            // means it went away. Clients must therefore not half-close
            // while they wait.
            let client_gone = async move {
                let _ = tokio::io::copy(&mut client, &mut tokio::io::sink()).await;
            };
            let out = m.run(&name, &argv, admin, limit, client_gone).await?;
            json!(ExecResult {
                exit_code: out.exit_code,
                stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
                truncated: out.truncated,
            })
        }
        Request::FileRead {
            name,
            path,
            offset,
            max_bytes,
            admin,
        } => {
            let max = usize::try_from(max_bytes.unwrap_or(api::FILE_READ_DEFAULT))?;
            let (data, more) = m.file_read(&name, &path, offset, max, admin).await?;
            let size = data.len() as u64;
            json!(api::FileData {
                data_base64: BASE64.encode(&data),
                size,
                more,
            })
        }
        Request::FileWrite {
            name,
            path,
            data_base64,
            append,
            admin,
        } => {
            let data = BASE64
                .decode(&data_base64)
                .context("data_base64 is not valid base64")?;
            m.file_write(&name, &path, &data, append, admin).await?;
            json!({"bytes": data.len()})
        }
        Request::Info { name } => {
            let vm = info(m, &m.load(&name)?).await;
            let (addresses, disk_used_bytes) = m.details(&name).await?;
            // The live socket: it exists only while the VM runs with VNC.
            let vnc_socket = Some(m.paths.vnc_socket(&name)).filter(|s| s.exists());
            json!(api::VmDetails {
                vm,
                addresses,
                disk_used_bytes,
                vnc_socket,
            })
        }
        Request::Reset { name } => {
            m.reset(&name).await?;
            Value::Null
        }
        Request::Rm { name } => {
            m.remove(&name).await?;
            Value::Null
        }
        Request::Screenshot { name } => screen(m.screenshot(&name).await?, None),
        Request::WaitForScreen {
            name,
            stable_ms,
            timeout_ms,
        } => {
            let stable = stable_ms.map_or(SCREEN_DEFAULT_STABLE, Duration::from_millis);
            let limit =
                timeout_ms.map_or(SCREEN_DEFAULT_TIMEOUT.max(stable), Duration::from_millis);
            let (shot, settled) = m.wait_for_screen(&name, stable, limit).await?;
            screen(shot, Some(settled))
        }
        Request::MouseMove { name, x, y } => {
            m.mouse_move(&name, x, y).await?;
            Value::Null
        }
        Request::Click {
            name,
            x,
            y,
            button,
            double,
            screenshot,
        } => {
            let button = button.unwrap_or(Button::Left);
            match m.click(&name, (x, y), button, double, screenshot).await? {
                Some(shot) => screen(shot, None),
                None => Value::Null,
            }
        }
        Request::Drag {
            name,
            from_x,
            from_y,
            to_x,
            to_y,
        } => {
            m.drag(&name, (from_x, from_y), (to_x, to_y)).await?;
            Value::Null
        }
        Request::Scroll { name, x, y, dy } => {
            m.scroll(&name, x, y, dy).await?;
            Value::Null
        }
        Request::TypeText { name, text } => {
            m.type_text(&name, &text).await?;
            Value::Null
        }
        Request::Key { name, keys } => {
            m.key(&name, &keys).await?;
            Value::Null
        }
        Request::SetAgent { name, on } => {
            m.set_agent(&name, on).await?;
            Value::Null
        }
        Request::SetVnc { name, on } => {
            m.set_vnc(&name, on).await?;
            json!({
                "running": m.running(&name).is_some(),
                "socket": on.then(|| m.paths.vnc_socket(&name)),
            })
        }
        Request::SetCdrom { name, iso } => {
            m.set_cdrom(&name, iso.as_deref()).await?;
            json!({
                "running": m.running(&name).is_some(),
                "cdrom": iso,
            })
        }
        Request::SetResources {
            name,
            vcpus,
            memory_mib,
        } => {
            let cfg = m.set_resources(&name, vcpus, memory_mib).await?;
            json!(info(m, &cfg).await)
        }
        Request::SetNet { name, net } => {
            let cfg = m.set_net(&name, net).await?;
            json!(info(m, &cfg).await)
        }
        Request::Resume { name } => {
            m.resume(&name).await?;
            Value::Null
        }
        Request::Snapshot { name, tag } => json!(m.snapshot(&name, tag.as_deref()).await?),
        Request::Snapshots { name } => json!(m.snapshots(&name).await?),
        Request::Restore { name, tag } => json!(m.restore(&name, tag.as_deref()).await?),
        Request::SnapshotDelete { name, tag } => {
            m.delete_snapshot(&name, &tag).await?;
            Value::Null
        }
        Request::Host => json!(m.host()?),
        Request::Images => {
            // Reads the images directory: off the async workers.
            let paths = m.paths.clone();
            let local = tokio::task::spawn_blocking(move || images::local_images(&paths)).await?;
            json!(
                images::catalog()
                    .into_iter()
                    .map(|e| {
                        let cached = images::is_cached(&m.paths, &e);
                        let size_bytes = std::fs::metadata(images::cached_path(&m.paths, &e))
                            .ok()
                            .filter(|f| f.is_file())
                            .map(|f| f.len());
                        let mut notes = vec![];
                        if size_bytes.is_some() && !cached {
                            notes.push("guest-agent packages not downloaded yet".into());
                        }
                        if e.trust == images::Trust::Pinned {
                            notes.push("pinned (upstream unsigned)".into());
                        }
                        if e.kind == images::Kind::Iso {
                            notes.push("install by hand over VNC; no guest agent".into());
                        }
                        if e.firmware == images::Firmware::Uefi {
                            notes.push("no Secure Boot".into());
                        }
                        let sig_date = size_bytes
                            .and_then(|_| images::pulled(&m.paths, &e.id))
                            .and_then(|p| p.sig_date);
                        ImageInfo {
                            cached,
                            kind: Some(e.kind),
                            os: Some(e.os),
                            trust: Some(e.trust),
                            size_bytes,
                            sig_date,
                            notes,
                            id: e.id,
                            name: e.name,
                        }
                    })
                    .chain(local)
                    .collect::<Vec<_>>()
            )
        }
        Request::Pull { image } => {
            m.pull(&image).await?;
            Value::Null
        }
        Request::ImageRm { image } => {
            m.remove_image(&image).await?;
            Value::Null
        }
        // The body is the ISO; humans only (Gate::Closed).
        Request::ImportIso { id, os, name, size } => {
            let record = m.import_iso(&id, os, &name, size, &mut client).await?;
            json!({"id": id, "sha256": record.sha256, "size": size})
        }
    })
}

/// A screenshot as response data. Built by hand so the multi-MiB base64
/// string is moved, not copied, into the JSON value.
fn screen(shot: Screenshot, stable: Option<bool>) -> Value {
    let png_base64 = BASE64.encode(&shot.png);
    drop(shot.png);
    let mut v = json!({"width": shot.width, "height": shot.height});
    v["png_base64"] = Value::String(png_base64);
    if let Some(stable) = stable {
        v["stable"] = stable.into();
    }
    v
}

/// A VM as `ls` shows it; the state comes from QEMU when it runs.
async fn info(m: &Manager, cfg: &VmConfig) -> VmInfo {
    let state = match m.running(&cfg.name) {
        None => "stopped".to_owned(),
        Some(vm) => vm.state().await,
    };
    VmInfo {
        name: cfg.name.clone(),
        state,
        vcpus: cfg.vcpus,
        memory_mib: cfg.memory_mib,
        disk_gib: cfg.disk_gib,
        net: cfg.net,
        forwards: cfg.forwards.clone(),
        agent_control: cfg.agent_control,
        vnc: cfg.vnc,
        image: Some(cfg.image.clone()),
        cdrom: cfg.cdrom.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use stallo::images::Os;
    use tokio::io::AsyncReadExt;

    /// A manager on temporary directories, as after the daemon's start.
    async fn manager(root: &std::path::Path) -> Arc<Manager> {
        for d in ["data", "run", "cg"] {
            std::fs::create_dir(root.join(d)).unwrap();
        }
        let paths = Paths::new(root.join("data"), root.join("run"))
            .unwrap()
            .prepare()
            .unwrap();
        let mut config = DaemonConfig::default();
        config.host.disk_floor_gib = 0;
        let m = Manager::new(paths, config, Cgroups::at(root.join("cg")), Mode::Dev);
        m.cleanup_leftovers().await.unwrap();
        m
    }

    /// Sends a request line and `body` over one connection, and returns
    /// the lines stallod answers until it closes the connection.
    async fn exchange(m: &Arc<Manager>, env: &Envelope, body: &[u8]) -> Vec<String> {
        let (client, server) = UnixStream::pair().unwrap();
        let own = rustix::process::getuid().as_raw();
        let served = {
            let m = m.clone();
            tokio::spawn(async move { connection(&m, server, own, None).await })
        };
        let (mut r, mut w) = client.into_split();
        let mut out = serde_json::to_vec(env).unwrap();
        out.push(b'\n');
        out.extend_from_slice(body);
        // A refusal comes before the body is read: send and read together.
        let send = async move {
            let _ = w.write_all(&out).await;
            let _ = w.shutdown().await;
        };
        let read = async {
            let (mut answer, mut buf) = (Vec::new(), [0; 4096]);
            // A close with the body unread may end in ECONNRESET.
            while let Ok(n @ 1..) = r.read(&mut buf).await {
                answer.extend_from_slice(&buf[..n]);
            }
            answer
        };
        let ((), answer) = tokio::join!(send, read);
        served.await.unwrap().unwrap();
        String::from_utf8(answer)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    /// `import_iso` end to end through `connection()`: a human's import
    /// lands and is audited with its SHA-256; an agent's is refused before
    /// its body is read, and the body is never taken for more requests.
    #[tokio::test]
    async fn import_over_the_socket() {
        let tmp = tempfile::tempdir().unwrap();
        let m = manager(&std::fs::canonicalize(tmp.path()).unwrap()).await;
        let mut iso = vec![0u8; 0x9000];
        iso[0x8001..0x8006].copy_from_slice(b"CD001");
        let import = |via| Envelope {
            via,
            request: Request::ImportIso {
                id: "local-x".into(),
                os: Os::Linux,
                name: "x".into(),
                size: iso.len() as u64,
            },
        };

        let smuggled = b"{\"via\":\"cli\",\"request\":{\"op\":\"list\"}}\n";
        let answer = exchange(&m, &import(Via::Mcp), smuggled).await;
        assert_eq!(answer.len(), 1, "{answer:?}");
        assert!(answer[0].contains("only available to humans"), "{answer:?}");
        assert!(!images::iso_path(&m.paths, "local-x").exists());

        let answer = exchange(&m, &import(Via::Cli), &iso).await;
        assert_eq!(answer.len(), 1, "{answer:?}");
        let response: Response = serde_json::from_str(&answer[0]).unwrap();
        assert!(response.ok, "{answer:?}");
        let sha: String = Sha256::digest(&iso)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(response.data["sha256"], sha.as_str());
        assert_eq!(
            std::fs::read(images::iso_path(&m.paths, "local-x")).unwrap(),
            iso
        );

        let log = std::fs::read_to_string(m.paths.audit_dir().join("_daemon.jsonl")).unwrap();
        let lines: Vec<serde_json::Value> = log
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 2, "{log}");
        assert_eq!(
            (&lines[0]["op"], &lines[0]["via"], &lines[0]["ok"]),
            (&json!("import_iso"), &json!("mcp"), &json!(false))
        );
        assert_eq!(lines[0].get("sha256"), None);
        assert_eq!(
            (&lines[1]["image"], &lines[1]["sha256"], &lines[1]["ok"]),
            (&json!("local-x"), &json!(sha), &json!(true))
        );
    }
}
