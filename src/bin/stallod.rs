//! stallod: the Stallo daemon. It owns every VM and serves the API socket.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::Parser;
use tokio::io::{AsyncWriteExt, BufReader};
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
use stallo::config::{DaemonConfig, VmConfig, validate_name};
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

#[derive(Parser)]
#[command(version, about = "Stallo daemon: owns VMs, serves the stallo API")]
struct Args {
    /// Dev mode: run as the current user with data under $HOME.
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
    if !args.dev {
        bail!("production mode is not available yet; run `stallod --dev`");
    }
    // New files are private to the daemon user (and its group in production).
    rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o027));

    let defaults = Paths::dev()?;
    let paths = Paths::new(
        args.data_dir.unwrap_or(defaults.data),
        args.runtime_dir.unwrap_or(defaults.runtime),
    )?
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
        .block_on(serve(paths, config, cgroups))?;
    drop(lock);
    Ok(())
}

async fn serve(paths: Paths, config: DaemonConfig, cgroups: Cgroups) -> Result<()> {
    let manager = Manager::new(paths.clone(), config, cgroups);
    manager.cleanup_leftovers().await?;

    let sock = paths.api_socket();
    safe_remove(&paths.runtime, &sock)?;
    let listener = UnixListener::bind(&sock).context("cannot bind the API socket")?;
    std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600))?;
    tracing::info!("listening on {}", sock.display());
    tokio::spawn(stallo::host::watchdog(manager.clone()));

    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let own_uid = rustix::process::getuid().as_raw();
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
                    if let Err(e) = connection(&manager, stream, own_uid).await {
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
    manager.stop_all().await;
    Ok(())
}

async fn connection(manager: &Arc<Manager>, stream: UnixStream, own_uid: u32) -> Result<()> {
    let cred = stream.peer_cred()?;
    if !api::authorize(cred.uid(), cred.gid(), own_uid, None) {
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
    let (response, audit) = match serde_json::from_slice::<Envelope>(&line) {
        Ok(env) => handle(manager, env, &cred).await,
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
/// cannot be audited is refused.
async fn handle(
    m: &Arc<Manager>,
    env: Envelope,
    peer: &UCred,
) -> (Response, Option<(std::fs::File, audit::Entry)>) {
    let started = Instant::now();
    let (op, vm, args, argv0) = audit::describe(&env.request);
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
            Ok(()) => dispatch(m, env.via, env.request).await,
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

async fn dispatch(m: &Arc<Manager>, via: Via, request: Request) -> Result<Value> {
    Ok(match request {
        Request::New {
            name,
            image,
            vcpus,
            memory_mib,
            disk_gib,
            net,
            wait,
        } => {
            let new = NewVm {
                name: name.clone(),
                image,
                vcpus,
                memory_mib,
                disk_gib,
                net,
                agent_control: via == Via::Mcp,
            };
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
            if wait {
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
            json!(api::VmDetails {
                vm,
                addresses,
                disk_used_bytes
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
        Request::Images => json!(
            images::catalog()
                .into_iter()
                .map(|e| ImageInfo {
                    cached: images::is_cached(&m.paths, &e),
                    id: e.id,
                    name: e.name,
                })
                .collect::<Vec<_>>()
        ),
        Request::Pull { image } => {
            m.pull(&image).await?;
            Value::Null
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
        agent_control: cfg.agent_control,
    }
}
