//! The I/O side. One tokio runtime on its own thread owns every socket and
//! file read; the GTK main thread only awaits the handles it gets back.

use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use stallo::api::{Envelope, Request, Via, VmDetails, VmInfo};
use stallo::host::HostInfo;
use stallo::paths::Paths;
use tokio::runtime::Handle;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

use crate::model::{self, CallError, Op, Probe, Production};

/// How long a read request may take, waiting for a free slot included.
pub const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Requests in flight at once, app-wide: 8, in two pools. Actions may
/// take up to 150 s each, so they have their own slots and reads (polls,
/// the probe) never wait behind them.
const READ_SLOTS: usize = 4;
const ACTION_SLOTS: usize = 4;
static READS: Semaphore = Semaphore::const_new(READ_SLOTS);
static ACTIONS: Semaphore = Semaphore::const_new(ACTION_SLOTS);

fn runtime() -> &'static Handle {
    static RT: OnceLock<Handle> = OnceLock::new();
    RT.get_or_init(|| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("cannot create the I/O runtime");
        let handle = rt.handle().clone();
        std::thread::Builder::new()
            .name("stallo-io".into())
            .spawn(move || rt.block_on(std::future::pending::<()>()))
            .expect("cannot start the I/O thread");
        handle
    })
}

/// Runs `fut` on the I/O thread.
pub fn spawn<F>(fut: F) -> JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    runtime().spawn(fut)
}

/// Sends one request; `limit` covers waiting for a slot and the answer.
async fn call_in(
    slots: &Semaphore,
    socket: &Path,
    request: Request,
    limit: Duration,
) -> Result<serde_json::Value, CallError> {
    // The app is a human interface, like the CLI.
    let envelope = Envelope {
        via: Via::Cli,
        request,
    };
    let work = async {
        let _slot = slots.acquire().await;
        stallo::api::call(socket, &envelope).await
    };
    match tokio::time::timeout(limit, work).await {
        Err(_) => Err(CallError::Timeout),
        Ok(Ok(data)) => Ok(data),
        Ok(Err(e)) => Err(
            match e
                .chain()
                .find_map(|c| c.downcast_ref::<io::Error>())
                .map(io::Error::kind)
            {
                Some(io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused) => {
                    CallError::NotRunning
                }
                Some(io::ErrorKind::PermissionDenied) => CallError::Denied,
                _ => CallError::Failed(format!("{e:#}")),
            },
        ),
    }
}

/// Sends a read request and parses the answer.
async fn get<T: serde::de::DeserializeOwned>(
    socket: &Path,
    request: Request,
    limit: Duration,
) -> Result<T, CallError> {
    let data = call_in(&READS, socket, request, limit).await?;
    serde_json::from_value(data)
        .map_err(|e| CallError::Failed(format!("unexpected answer from stallod: {e}")))
}

/// The VMs (`list`).
pub async fn list(socket: &Path, limit: Duration) -> Result<Vec<VmInfo>, CallError> {
    get(socket, Request::List, limit).await
}

/// Host resources and the VM budget (`host`).
pub async fn host(socket: &Path) -> Result<HostInfo, CallError> {
    get(socket, Request::Host, READ_TIMEOUT).await
}

/// One VM with its addresses and disk use (`info`).
pub async fn info(socket: &Path, name: String) -> Result<VmDetails, CallError> {
    get(socket, Request::Info { name }, READ_TIMEOUT).await
}

/// Starts, stops, resets or resumes a VM.
pub async fn act(socket: &Path, op: Op, name: &str) -> Result<(), CallError> {
    call_in(&ACTIONS, socket, op.request(name), op.limit())
        .await
        .map(drop)
}

/// Looks at the host and, when that leaves a socket to try, asks it.
pub async fn probe() -> Probe {
    let mut p = tokio::task::spawn_blocking(local_probe)
        .await
        .expect("the host probe panicked");
    if let Some(socket) = model::socket(&p) {
        p.list = Some(list(&socket, READ_TIMEOUT).await.map(|vms| vms.len()));
    }
    p
}

/// Blocking: file metadata and /etc/group only, nothing that needs root.
fn local_probe() -> Probe {
    let production = Paths::production().map(|p| p.api_socket());
    let production = match production.map(std::fs::metadata) {
        Ok(Ok(_)) => Production::Up,
        // `/run/stallo` is only open to group `stallo`.
        Ok(Err(e)) if e.kind() == io::ErrorKind::PermissionDenied => Production::Denied,
        _ => Production::Missing,
    };
    let dev = Paths::dev().ok().map(|p| p.api_socket());
    let gids: Vec<u32> = rustix::process::getgroups()
        .unwrap_or_default()
        .into_iter()
        .chain([rustix::process::getgid()])
        .map(|g| g.as_raw())
        .collect();
    Probe {
        kvm: Path::new("/dev/kvm").exists(),
        explicit: std::env::var_os("STALLO_SOCKET").map(PathBuf::from),
        production,
        dev_up: dev.as_ref().is_some_and(|d| d.exists()),
        dev,
        // The same name the usermod command we show adds.
        group: model::group(
            &std::fs::read_to_string("/etc/group").unwrap_or_default(),
            &std::env::var("USER").unwrap_or_default(),
            &gids,
        ),
        list: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{UnixListener, UnixStream};

    fn run<T: Send + 'static>(fut: impl Future<Output = T> + Send + 'static) -> T {
        runtime().block_on(spawn(fut)).unwrap()
    }

    fn list_at(socket: &Path, limit: Duration) -> Result<usize, CallError> {
        let socket = socket.to_owned();
        run(async move { list(&socket, limit).await.map(|v| v.len()) })
    }

    /// A one-connection fake daemon that checks the request line and then
    /// does `reply`. The test fails if the request is not `expect`.
    fn serve(
        expect: &'static str,
        reply: impl FnOnce(UnixStream) + Send + 'static,
    ) -> (tempfile::TempDir, PathBuf, std::thread::JoinHandle<()>) {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("api.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let fake = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(&stream).read_line(&mut line).unwrap();
            assert_eq!(line, format!("{{\"via\":\"cli\",\"request\":{expect}}}\n"));
            reply(stream);
        });
        (dir, socket, fake)
    }

    fn daemon(reply: impl FnOnce(UnixStream) + Send + 'static) -> (tempfile::TempDir, PathBuf) {
        let (dir, socket, _) = serve(r#"{"op":"list"}"#, reply);
        (dir, socket)
    }

    const VM: &str = r#"{"name":"dev","state":"running","vcpus":2,"memory_mib":2048,"disk_gib":20,"net":"internet","forwards":[{"bind":"127.0.0.1","host":8080,"guest":80}],"agent_control":true}"#;

    fn answer(text: &'static str) -> impl FnOnce(UnixStream) + Send {
        move |mut s| s.write_all(text.as_bytes()).unwrap()
    }

    #[test]
    fn lists() {
        let reply = format!("{{\"ok\":true,\"data\":[{VM},{VM}]}}\n");
        let (_d, s) = daemon(move |mut s| s.write_all(reply.as_bytes()).unwrap());
        let vms = run(async move { list(&s, READ_TIMEOUT).await }).unwrap();
        assert_eq!(vms.len(), 2);
        assert_eq!(vms[0].name, "dev");
        assert!(vms[0].agent_control && !vms[0].vnc);
        assert_eq!(vms[0].forwards[0].guest, 80);
        // Not a VM list: an error, not a guess.
        let (_d, s) = daemon(answer("{\"ok\":true,\"data\":[{\"name\":\"a\"}]}\n"));
        match list_at(&s, READ_TIMEOUT) {
            Err(CallError::Failed(e)) => assert!(e.contains("unexpected answer"), "{e}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn host_and_info() {
        let (_d, s, fake) = serve(
            r#"{"op":"host"}"#,
            answer(concat!(
                r#"{"ok":true,"data":{"cores":8,"vcpus_allotted":2,"memory_total_mib":32000,"#,
                r#""memory_available_mib":20000,"memory_budget_mib":24000,"memory_used_mib":3000,"#,
                r#""disk_free_bytes":1000,"disk_floor_gib":20,"running_vms":1}}"#,
                "\n"
            )),
        );
        let host = run(async move { host(&s).await }).unwrap();
        fake.join().unwrap();
        assert_eq!((host.memory_used_mib, host.disk_floor_gib), (3000, 20));

        let reply = format!(
            "{{\"ok\":true,\"data\":{},\"addresses\":[[\"eth0\",\"10.0.2.15/24\"]],\"disk_used_bytes\":42}}}}\n",
            &VM[..VM.len() - 1]
        );
        let (_d, s, fake) = serve(r#"{"op":"info","name":"dev"}"#, move |mut s| {
            s.write_all(reply.as_bytes()).unwrap()
        });
        let d = run(async move { info(&s, "dev".into()).await }).unwrap();
        fake.join().unwrap();
        assert_eq!(d.vm.name, "dev");
        assert_eq!(d.disk_used_bytes, 42);
        assert_eq!(
            d.addresses,
            Some(vec![("eth0".to_owned(), "10.0.2.15/24".to_owned())])
        );
    }

    #[test]
    fn actions() {
        for (op, line) in [
            (Op::Start, r#"{"op":"start","name":"dev","wait":false}"#),
            (Op::Stop, r#"{"op":"stop","name":"dev","force":false}"#),
            (Op::ForceOff, r#"{"op":"stop","name":"dev","force":true}"#),
            (Op::Reset, r#"{"op":"reset","name":"dev"}"#),
            (Op::Resume, r#"{"op":"resume","name":"dev"}"#),
        ] {
            let (_d, s, fake) = serve(line, answer("{\"ok\":true}\n"));
            let done = run(async move { act(&s, op, "dev").await });
            fake.join().unwrap();
            assert_eq!(done, Ok(()), "{op:?}");
        }
        let (_d, s, _) = serve(
            r#"{"op":"resume","name":"dev"}"#,
            answer("{\"ok\":false,\"error\":\"dev is not paused\"}\n"),
        );
        assert_eq!(
            run(async move { act(&s, Op::Resume, "dev").await }),
            Err(CallError::Failed("dev is not paused".into()))
        );
    }

    #[test]
    fn daemon_errors() {
        let (_d, s) = daemon(answer("{\"ok\":false,\"error\":\"no such vm\"}\n"));
        assert_eq!(
            list_at(&s, READ_TIMEOUT),
            Err(CallError::Failed("no such vm".into()))
        );
        let (_d, s) = daemon(answer("{\"ok\":true,\"data\":{}}\n"));
        assert!(matches!(
            list_at(&s, READ_TIMEOUT),
            Err(CallError::Failed(_))
        ));
        let (_d, s) = daemon(answer("not json\n"));
        assert!(matches!(
            list_at(&s, READ_TIMEOUT),
            Err(CallError::Failed(_))
        ));
        let (_d, s) = daemon(drop);
        assert!(matches!(
            list_at(&s, READ_TIMEOUT),
            Err(CallError::Failed(_))
        ));
    }

    #[test]
    fn times_out() {
        // Never answers; holds the connection until the client gives up.
        let (_d, s) = daemon(|mut s| {
            let _ = s.read_to_end(&mut Vec::new());
        });
        assert_eq!(
            list_at(&s, Duration::from_millis(200)),
            Err(CallError::Timeout)
        );
    }

    #[test]
    fn not_running() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.sock");
        assert_eq!(list_at(&missing, READ_TIMEOUT), Err(CallError::NotRunning));
        // A stale socket file nobody listens on: ECONNREFUSED.
        let stale = dir.path().join("stale.sock");
        drop(UnixListener::bind(&stale).unwrap());
        assert_eq!(list_at(&stale, READ_TIMEOUT), Err(CallError::NotRunning));
    }

    #[test]
    fn permission_denied() {
        if rustix::process::geteuid().is_root() {
            return; // root ignores file modes
        }
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("api.sock");
        let _listener = UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o000)).unwrap();
        assert_eq!(list_at(&socket, READ_TIMEOUT), Err(CallError::Denied));
    }

    #[test]
    fn waiting_for_a_slot_counts() {
        let (_d, s) = daemon(answer("{\"ok\":true,\"data\":[]}\n"));
        let slots = std::sync::Arc::new(Semaphore::new(READ_SLOTS));
        let held = runtime()
            .block_on(slots.clone().acquire_many_owned(READ_SLOTS as u32))
            .unwrap();
        let call = |slots: std::sync::Arc<Semaphore>, s: PathBuf| {
            run(async move { call_in(&slots, &s, Request::List, Duration::from_millis(200)).await })
        };
        // With every slot taken, the next request never gets one, so it never connects.
        assert_eq!(call(slots.clone(), s.clone()), Err(CallError::Timeout));
        drop(held);
        assert_eq!(call(slots, s), Ok(serde_json::json!([])));
    }

    #[test]
    fn reads_pass_busy_actions() {
        // Every action slot taken, e.g. by slow stops.
        let held = runtime()
            .block_on(ACTIONS.acquire_many(ACTION_SLOTS as u32))
            .unwrap();
        let (_d, s) = daemon(answer("{\"ok\":true,\"data\":[]}\n"));
        assert_eq!(list_at(&s, READ_TIMEOUT), Ok(0));
        let (_d, s, _) = serve(r#"{"op":"reset","name":"dev"}"#, answer("{\"ok\":true}\n"));
        let wait = run(async move {
            call_in(
                &ACTIONS,
                &s,
                Op::Reset.request("dev"),
                Duration::from_millis(200),
            )
            .await
        });
        assert_eq!(wait, Err(CallError::Timeout), "actions still queue");
        drop(held);
    }

    #[test]
    fn oversized_answer() {
        let (_d, s) = daemon(|mut s| {
            let chunk = vec![b'a'; 1 << 20];
            for _ in 0..=stallo::api::MAX_RESPONSE / chunk.len() {
                if s.write_all(&chunk).is_err() {
                    return; // the client gave up, as it should
                }
            }
            let _ = s.write_all(b"\n");
        });
        match list_at(&s, READ_TIMEOUT) {
            Err(CallError::Failed(e)) => assert!(e.contains("longer than"), "{e}"),
            other => panic!("{other:?}"),
        }
    }
}
