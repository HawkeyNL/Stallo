//! The I/O side. One tokio runtime on its own thread owns every socket and
//! file read; the GTK main thread only awaits the handles it gets back.

use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use stallo::api::{Envelope, Request, Via};
use stallo::paths::Paths;
use tokio::runtime::Handle;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

use crate::model::{self, CallError, Probe, Production};

/// How long a read request may take, waiting for a free slot included.
pub const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Requests in flight at once, app-wide.
const MAX_IN_FLIGHT: usize = 8;

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
pub async fn call(
    socket: &Path,
    request: Request,
    limit: Duration,
) -> Result<serde_json::Value, CallError> {
    static SLOTS: Semaphore = Semaphore::const_new(MAX_IN_FLIGHT);
    call_in(&SLOTS, socket, request, limit).await
}

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

/// The number of VMs (`list`).
pub async fn list(socket: &Path, limit: Duration) -> Result<usize, CallError> {
    let data = call(socket, Request::List, limit).await?;
    data.as_array()
        .map(Vec::len)
        .ok_or_else(|| CallError::Failed("unexpected answer to list".into()))
}

/// Looks at the host and, when that leaves a socket to try, asks it.
pub async fn probe() -> Probe {
    let mut p = tokio::task::spawn_blocking(local_probe)
        .await
        .expect("the host probe panicked");
    if let Some(socket) = model::socket(&p) {
        p.list = Some(list(&socket, READ_TIMEOUT).await);
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
        run(async move { list(&socket, limit).await })
    }

    /// A one-connection fake daemon that reads the request line and then
    /// does `reply`.
    fn daemon(reply: impl FnOnce(UnixStream) + Send + 'static) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("api.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(&stream).read_line(&mut line).unwrap();
            assert_eq!(line, "{\"via\":\"cli\",\"request\":{\"op\":\"list\"}}\n");
            reply(stream);
        });
        (dir, socket)
    }

    fn answer(text: &'static str) -> impl FnOnce(UnixStream) + Send {
        move |mut s| s.write_all(text.as_bytes()).unwrap()
    }

    #[test]
    fn lists() {
        let (_d, s) = daemon(answer(
            "{\"ok\":true,\"data\":[{\"name\":\"a\"},{\"name\":\"b\"}]}\n",
        ));
        assert_eq!(list_at(&s, READ_TIMEOUT), Ok(2));
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
        let slots = std::sync::Arc::new(Semaphore::new(MAX_IN_FLIGHT));
        let held = runtime()
            .block_on(slots.clone().acquire_many_owned(MAX_IN_FLIGHT as u32))
            .unwrap();
        let call = |slots: std::sync::Arc<Semaphore>, s: PathBuf| {
            run(async move { call_in(&slots, &s, Request::List, Duration::from_millis(200)).await })
        };
        // The ninth request never gets a slot, so it never connects.
        assert_eq!(call(slots.clone(), s.clone()), Err(CallError::Timeout));
        drop(held);
        assert_eq!(call(slots, s), Ok(serde_json::json!([])));
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
