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

use serde_json::{Value, json};
use stallo::api::{self, Envelope, ExecResult, ImageInfo, NewResult, Request, Response, VmInfo};
use stallo::cgroup::Cgroups;
use stallo::config::{DaemonConfig, VmConfig};
use stallo::images;
use stallo::paths::{Paths, safe_remove};
use stallo::read_line;
use stallo::vm::{EXEC_DEFAULT_TIMEOUT, Manager, NewVm, READY_TIMEOUT};
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
    let response = match serde_json::from_slice::<Envelope>(&line) {
        Ok(env) => handle(manager, env, &cred).await,
        Err(e) => {
            tracing::info!(
                "invalid request from uid {} pid {:?}",
                cred.uid(),
                cred.pid()
            );
            Response::err(&anyhow::anyhow!("invalid request: {e}"))
        }
    };
    let mut out = serde_json::to_vec(&response)?;
    if out.len() > api::MAX_RESPONSE {
        out = serde_json::to_vec(&Response::err(&anyhow::anyhow!("response too large")))?;
    }
    out.push(b'\n');
    tokio::time::timeout(Duration::from_secs(30), w.write_all(&out))
        .await
        .context("response write timed out")??;
    Ok(())
}

/// Runs one API request and logs it (operation, caller, result, duration;
/// never arguments).
async fn handle(m: &Arc<Manager>, env: Envelope, peer: &UCred) -> Response {
    let started = Instant::now();
    let op = op_name(&env.request);
    let result = dispatch(m, env.request).await;
    tracing::info!(
        "{op} via {:?} from uid {} pid {:?}: {} in {} ms",
        env.via,
        peer.uid(),
        peer.pid(),
        if result.is_ok() { "ok" } else { "error" },
        started.elapsed().as_millis()
    );
    match result {
        Ok(data) => Response {
            ok: true,
            data,
            error: None,
        },
        Err(e) => Response::err(&e),
    }
}

fn op_name(r: &Request) -> &'static str {
    match r {
        Request::New { .. } => "new",
        Request::List => "list",
        Request::Start { .. } => "start",
        Request::Stop { .. } => "stop",
        Request::Exec { .. } => "exec",
        Request::Rm { .. } => "rm",
        Request::Images => "images",
        Request::Pull { .. } => "pull",
    }
}

async fn dispatch(m: &Arc<Manager>, request: Request) -> Result<Value> {
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
        } => {
            let limit = timeout_s.map_or(EXEC_DEFAULT_TIMEOUT, Duration::from_secs);
            let out = m.exec(&name, &argv, admin, limit).await?;
            json!(ExecResult {
                exit_code: out.exit_code,
                stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
                truncated: out.truncated,
            })
        }
        Request::Rm { name } => {
            m.remove(&name).await?;
            Value::Null
        }
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

/// A VM as `ls` shows it; the state comes from QEMU when it runs.
async fn info(m: &Manager, cfg: &VmConfig) -> VmInfo {
    let state = match m.running(&cfg.name) {
        None => "stopped".to_owned(),
        Some(vm) => vm.status().await.unwrap_or_else(|_| "unknown".to_owned()),
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
