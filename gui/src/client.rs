//! The I/O side. One tokio runtime on its own thread owns every socket and
//! file read; the GTK main thread only awaits the handles it gets back.

use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::OnceLock;
use std::task::{Context, Poll};
use std::time::Duration;

use stallo::api::{Envelope, ImageInfo, Request, Via, VmDetails, VmInfo};
use stallo::host::HostInfo;
use stallo::images::{IMPORT_TOTAL, MAX_IMPORT_BYTES, Os};
use stallo::paths::Paths;
use stallo::snapshot::Snapshot;
use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};
use tokio::runtime::Handle;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinHandle;

use crate::model::{self, Action, CallError, Probe, Production};

/// How long a read request may take, waiting for a free slot included.
pub const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Requests in flight at once, app-wide: 15, in five pools. Lifecycle
/// actions may take up to 150 s each, snapshot actions 15 min, creates
/// (with an image download) 30 min and file copies one request per chunk,
/// so each kind has its own slots: reads (polls, the probe) never wait
/// behind an action, a start or stop never waits behind a snapshot job or
/// a copy, and nothing waits behind a create. The window runs one create
/// at a time.
const READ_SLOTS: usize = 4;
const ACTION_SLOTS: usize = 4;
const SNAP_SLOTS: usize = 4;
const CREATE_SLOTS: usize = 1;
const FILE_SLOTS: usize = 2;
static READS: Semaphore = Semaphore::const_new(READ_SLOTS);
static ACTIONS: Semaphore = Semaphore::const_new(ACTION_SLOTS);
static SNAPS: Semaphore = Semaphore::const_new(SNAP_SLOTS);
static CREATES: Semaphore = Semaphore::const_new(CREATE_SLOTS);
static FILES: Semaphore = Semaphore::const_new(FILE_SLOTS);

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
    let work = async {
        let _slot = slots.acquire().await;
        send(socket, request, limit).await
    };
    tokio::time::timeout(limit, work)
        .await
        .unwrap_or(Err(CallError::Timeout))
}

/// Sends one request, without a slot; `limit` covers the answer.
async fn send(
    socket: &Path,
    request: Request,
    limit: Duration,
) -> Result<serde_json::Value, CallError> {
    // The app is a human interface, like the CLI.
    let envelope = Envelope {
        via: Via::Cli,
        request,
    };
    match tokio::time::timeout(limit, stallo::api::call(socket, &envelope)).await {
        Err(_) => Err(CallError::Timeout),
        Ok(result) => result.map_err(call_error),
    }
}

fn call_error(e: anyhow::Error) -> CallError {
    match e
        .chain()
        .find_map(|c| c.downcast_ref::<io::Error>())
        .map(io::Error::kind)
    {
        Some(io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused) => CallError::NotRunning,
        Some(io::ErrorKind::PermissionDenied) => CallError::Denied,
        _ => CallError::Failed(format!("{e:#}")),
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

/// A VM's snapshots, oldest first (`snapshots`).
pub async fn snapshots(socket: &Path, name: String) -> Result<Vec<Snapshot>, CallError> {
    get(socket, Request::Snapshots { name }, READ_TIMEOUT).await
}

/// Changes a VM: a lifecycle or snapshot action. Returns the last answer,
/// or the index of the request that failed (see [`Action::failed_at`])
/// and why.
pub async fn act(
    socket: &Path,
    action: &Action,
    name: &str,
) -> Result<serde_json::Value, (usize, CallError)> {
    // ponytail: waiting for a slot still counts against the limit, so a
    // fifth snapshot action at once may time out unsent; fine for 4 slots.
    let slots = if action.lifecycle() { &ACTIONS } else { &SNAPS };
    let mut answer = serde_json::Value::Null;
    for (step, request) in action.requests(name).into_iter().enumerate() {
        answer = call_in(slots, socket, request, action.limit())
            .await
            .map_err(|e| (step, e))?;
    }
    Ok(answer)
}

/// The images VMs can be created from (`images`).
pub async fn images(socket: &Path) -> Result<Vec<ImageInfo>, CallError> {
    get(socket, Request::Images, READ_TIMEOUT).await
}

/// Creates a VM (`new`), downloading its image first if needed.
pub async fn create(socket: &Path, request: Request) -> Result<serde_json::Value, CallError> {
    call_in(&CREATES, socket, request, model::CREATE_LIMIT).await
}

/// One part of a file copy (`file_read`, `file_write`). The time limit
/// starts once it has a slot: a copy waits for another copy's chunk, not
/// for the whole other copy to fit in its own limit.
pub async fn file(socket: &Path, request: Request) -> Result<serde_json::Value, CallError> {
    let _slot = FILES.acquire().await;
    send(socket, request, model::FILE_LIMIT).await
}

/// The time limit of an ISO import: the daemon's own, and its answer.
const IMPORT_LIMIT: Duration = Duration::from_secs(IMPORT_TOTAL.as_secs() + 60);

/// Imports the ISO at `path` as image `id` (`import_iso`), as `stallo
/// images import` does: opened with the user's own rights, then exactly
/// its size streamed to the daemon, which never sees the path. File reads
/// run on the blocking pool, 1 MiB at a time; `sent` follows the bytes
/// read, and the size. Dropping the future (an aborted task) closes the
/// stream, and the daemon drops what it got. No slot: the New VM dialog
/// runs one import at a time.
pub async fn import(
    socket: PathBuf,
    path: PathBuf,
    id: String,
    os: Os,
    sent: watch::Sender<(u64, u64)>,
) -> Result<serde_json::Value, CallError> {
    let host = |e: io::Error| CallError::Failed(format!("cannot open {}: {e}", path.display()));
    // Non-blocking, so a FIFO cannot hang open(); regular files ignore it.
    let file = tokio::fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32)
        .open(&path)
        .await
        .map_err(host)?;
    let meta = file.metadata().await.map_err(host)?;
    let size = meta.len();
    if !meta.is_file() {
        return Err(CallError::Failed("not a regular file".to_owned()));
    }
    if size > MAX_IMPORT_BYTES {
        return Err(CallError::Failed(format!(
            "larger than {} GiB",
            MAX_IMPORT_BYTES >> 30
        )));
    }
    sent.send_replace((0, size));
    let name = path
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    let envelope = Envelope {
        via: Via::Cli,
        request: Request::ImportIso { id, os, name, size },
    };
    // `take`: a file that grows meanwhile sends `size` bytes all the same.
    let body = Counted {
        inner: tokio::io::BufReader::with_capacity(1 << 20, file.take(size)),
        done: 0,
        size,
        sent,
    };
    tokio::time::timeout(IMPORT_LIMIT, stallo::api::upload(&socket, &envelope, body))
        .await
        .map_err(|_| CallError::Timeout)?
        .map_err(call_error)
}

/// Counts the bytes read through it into `sent`: every 16 MiB and at the
/// end, which is all a progress bar needs.
struct Counted<R> {
    inner: R,
    done: u64,
    size: u64,
    sent: watch::Sender<(u64, u64)>,
}

impl<R: AsyncRead + Unpin> AsyncRead for Counted<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let poll = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = poll {
            let n = (buf.filled().len() - before) as u64;
            let old = this.done;
            this.done += n;
            if n == 0 || old >> 24 != this.done >> 24 {
                this.sent.send_replace((this.done, this.size));
            }
        }
        poll
    }
}

/// Runs host file work off the I/O thread.
pub async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, CallError> + Send + 'static,
) -> Result<T, CallError> {
    tokio::task::spawn_blocking(work)
        .await
        .unwrap_or_else(|e| Err(CallError::Failed(e.to_string())))
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
    use crate::model::Op;
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
            let done = run(async move { act(&s, &Action::Life(op), "dev").await });
            fake.join().unwrap();
            assert_eq!(done, Ok(serde_json::Value::Null), "{op:?}");
        }
        let (_d, s, _) = serve(
            r#"{"op":"resume","name":"dev"}"#,
            answer("{\"ok\":false,\"error\":\"dev is not paused\"}\n"),
        );
        assert_eq!(
            run(async move { act(&s, &Action::Life(Op::Resume), "dev").await }),
            Err((0, CallError::Failed("dev is not paused".into())))
        );
    }

    #[test]
    fn snapshot_requests() {
        let (_d, s, fake) = serve(
            r#"{"op":"snapshots","name":"dev"}"#,
            answer(concat!(
                r#"{"ok":true,"data":[{"name":"s1","ram_bytes":0,"created":10,"vm_clock_ms":0},"#,
                r#"{"name":"s2","ram_bytes":4096,"created":20,"vm_clock_ms":7}]}"#,
                "\n"
            )),
        );
        let list = run(async move { snapshots(&s, "dev".into()).await }).unwrap();
        fake.join().unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!((list[1].name.as_str(), list[1].ram_bytes), ("s2", 4096));
        let (_d, s, _) = serve(
            r#"{"op":"snapshots","name":"dev"}"#,
            answer("{\"ok\":true,\"data\":[{\"name\":\"s1\"}]}\n"),
        );
        assert!(matches!(
            run(async move { snapshots(&s, "dev".into()).await }),
            Err(CallError::Failed(_))
        ));

        for (action, line, reply) in [
            (
                Action::Take(None),
                r#"{"op":"snapshot","name":"dev","tag":null}"#,
                r#"{"ok":true,"data":{"name":"snap1","ram":true,"pause_ms":2200,"ms":2500}}"#,
            ),
            (
                Action::Take(Some("s1".into())),
                r#"{"op":"snapshot","name":"dev","tag":"s1"}"#,
                r#"{"ok":true,"data":{"name":"s1","ram":false,"ms":300}}"#,
            ),
            (
                Action::Restore("s1".into()),
                r#"{"op":"restore","name":"dev","tag":"s1"}"#,
                r#"{"ok":true,"data":{"name":"s1","state":"stopped","ms":300}}"#,
            ),
            (
                Action::Delete("s1".into()),
                r#"{"op":"snapshot_delete","name":"dev","tag":"s1"}"#,
                r#"{"ok":true}"#,
            ),
        ] {
            let (_d, s, fake) = serve(line, move |mut s| {
                s.write_all(format!("{reply}\n").as_bytes()).unwrap()
            });
            let a = action.clone();
            let got = run(async move { act(&s, &a, "dev").await });
            fake.join().unwrap();
            let want: serde_json::Value = serde_json::from_str(reply).unwrap();
            assert_eq!(got, Ok(want["data"].clone()), "{action:?}");
        }
        let (_d, s, _) = serve(
            r#"{"op":"restore","name":"dev","tag":"s2"}"#,
            answer("{\"ok\":false,\"error\":\"s2 has no RAM state; stop the VM first\"}\n"),
        );
        assert_eq!(
            run(async move { act(&s, &Action::Restore("s2".into()), "dev").await }),
            Err((
                0,
                CallError::Failed("s2 has no RAM state; stop the VM first".into())
            ))
        );
    }

    #[test]
    fn image_and_create_requests() {
        let (_d, s, fake) = serve(
            r#"{"op":"images"}"#,
            answer(concat!(
                r#"{"ok":true,"data":[{"id":"arch","name":"Arch","cached":false},"#,
                r#"{"id":"ubuntu-26.04","name":"Ubuntu","cached":true,"os":"linux","size_bytes":7}]}"#,
                "\n"
            )),
        );
        let list = run(async move { images(&s).await }).unwrap();
        fake.join().unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!((list[1].cached, list[1].size_bytes), (true, Some(7)));

        let (_d, s, fake) = serve(
            r#"{"op":"new","name":"web","image":"arch","vcpus":2,"memory_mib":2048,"disk_gib":20,"net":"offline","wait":true}"#,
            answer("{\"ok\":true,\"data\":{\"ready_ms\":9}}\n"),
        );
        let new = Request::New {
            name: "web".into(),
            image: "arch".into(),
            vcpus: 2,
            memory_mib: 2048,
            disk_gib: 20,
            net: stallo::config::NetProfile::Offline,
            forwards: vec![],
            wait: true,
            vnc: false,
        };
        assert_eq!(
            run(async move { create(&s, new).await }),
            Ok(serde_json::json!({"ready_ms": 9}))
        );
        fake.join().unwrap();
    }

    #[test]
    fn file_requests() {
        let (_d, s, fake) = serve(
            r#"{"op":"file_read","name":"dev","path":"/tmp/a","offset":0,"max_bytes":8388608,"admin":false}"#,
            answer("{\"ok\":true,\"data\":{\"data_base64\":\"aGk=\",\"size\":2,\"more\":false}}\n"),
        );
        let data =
            run(async move { file(&s, model::read_request("dev", "/tmp/a", 0, false)).await });
        fake.join().unwrap();
        assert_eq!(
            model::read_answer(data.unwrap(), 0),
            Ok((b"hi".to_vec(), false))
        );
        // Host file work runs off the I/O thread; a panic is an error.
        assert_eq!(run(async { blocking(|| Ok(7)).await }), Ok(7));
        assert!(matches!(
            run(async { blocking(|| -> Result<(), CallError> { panic!("boom") }).await }),
            Err(CallError::Failed(_))
        ));
    }

    /// A one-connection fake daemon for a request with a body: `then`
    /// gets the request line and the stream right after it.
    fn upload_daemon<T: Send + 'static>(
        then: impl FnOnce(String, BufReader<UnixStream>) -> T + Send + 'static,
    ) -> (tempfile::TempDir, PathBuf, std::thread::JoinHandle<T>) {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("api.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let fake = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut r = BufReader::new(stream);
            let mut line = String::new();
            r.read_line(&mut line).unwrap();
            then(line, r)
        });
        (dir, socket, fake)
    }

    fn iso_file(dir: &Path, len: usize) -> PathBuf {
        let path = dir.join("Win11 25H2.iso");
        std::fs::write(&path, (0..len).map(|i| i as u8).collect::<Vec<_>>()).unwrap();
        path
    }

    #[test]
    fn import_streams_the_file() {
        // Over two progress steps, and not a whole number of reads.
        let len = (40 << 20) + 5;
        let (dir, socket, fake) = upload_daemon(move |line, mut r| {
            let mut body = Vec::new();
            r.read_to_end(&mut body).unwrap(); // up to the half-close
            let answer =
                format!("{{\"ok\":true,\"data\":{{\"id\":\"local-win11\",\"size\":{len}}}}}\n");
            r.get_mut().write_all(answer.as_bytes()).unwrap();
            (line, body)
        });
        let path = iso_file(dir.path(), len);
        let (sent, progress) = watch::channel((0, 0));
        let p = path.clone();
        let got =
            run(async move { import(socket, p, "local-win11".into(), Os::Windows, sent).await });
        assert_eq!(got.unwrap()["size"], len as u64);
        let (line, body) = fake.join().unwrap();
        assert_eq!(
            line,
            format!(
                "{{\"via\":\"cli\",\"request\":{{\"op\":\"import_iso\",\"id\":\"local-win11\",\"os\":\"windows\",\"name\":\"Win11 25H2\",\"size\":{len}}}}}\n"
            )
        );
        assert!(
            body == std::fs::read(&path).unwrap(),
            "the body is the file"
        );
        assert_eq!(*progress.borrow(), (len as u64, len as u64));
    }

    #[test]
    fn import_cancel_closes_the_stream() {
        let len = 8 << 20;
        let (go, wait) = std::sync::mpsc::channel::<()>();
        // Reads nothing until the client gave up, then all there is.
        let (dir, socket, fake) = upload_daemon(move |_, mut r| {
            wait.recv().unwrap();
            let mut body = Vec::new();
            r.read_to_end(&mut body).unwrap();
            body.len()
        });
        let path = iso_file(dir.path(), len);
        let (sent, mut progress) = watch::channel((0, 0));
        let task = spawn(import(socket, path, "local-x".into(), Os::Linux, sent));
        // Sending: the size is known, the socket's buffer fills up.
        runtime()
            .block_on(progress.wait_for(|&(_, size)| size == len as u64))
            .unwrap();
        std::thread::sleep(Duration::from_millis(100));
        assert!(!task.is_finished(), "a daemon that reads nothing holds it");
        task.abort();
        assert!(runtime().block_on(task).unwrap_err().is_cancelled());
        go.send(()).unwrap();
        // The stream ended (EOF) short of the size: the daemon drops it.
        assert!(fake.join().unwrap() < len);
    }

    #[test]
    fn import_errors() {
        // Refused before the body is read: the answer, not a broken pipe.
        let refusal = "an image pull or import is in progress; try again when it ends";
        let (dir, socket, fake) = upload_daemon(move |_, mut r| {
            let answer = format!("{{\"ok\":false,\"error\":\"{refusal}\"}}\n");
            r.get_mut().write_all(answer.as_bytes()).unwrap();
        });
        let path = iso_file(dir.path(), 4 << 20);
        let (sent, _) = watch::channel((0, 0));
        let got = run(async move { import(socket, path, "local-x".into(), Os::Linux, sent).await });
        fake.join().unwrap();
        assert_eq!(got, Err(CallError::Failed(refusal.into())));

        // Refused here, before any connection.
        let dir = tempfile::tempdir().unwrap();
        let nowhere = dir.path().join("api.sock");
        let local = |path: PathBuf| {
            let (sent, _) = watch::channel((0, 0));
            let socket = nowhere.clone();
            run(async move { import(socket, path, "local-x".into(), Os::Linux, sent).await })
        };
        assert_eq!(
            local(dir.path().to_owned()),
            Err(CallError::Failed("not a regular file".into()))
        );
        assert!(matches!(
            local(dir.path().join("missing.iso")),
            Err(CallError::Failed(e)) if e.starts_with("cannot open ")
        ));
        // No daemon.
        assert_eq!(local(iso_file(dir.path(), 10)), Err(CallError::NotRunning));
    }

    #[test]
    fn restart_sends_its_requests_in_turn() {
        // Answers each connection with the next reply; returns the lines.
        let daemon = |replies: Vec<&'static str>| {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("api.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            let fake = std::thread::spawn(move || {
                let mut lines = Vec::new();
                for reply in replies {
                    let (mut stream, _) = listener.accept().unwrap();
                    let mut line = String::new();
                    BufReader::new(&stream).read_line(&mut line).unwrap();
                    lines.push(line);
                    stream.write_all(reply.as_bytes()).unwrap();
                }
                lines
            });
            (dir, socket, fake)
        };
        let ok = "{\"ok\":true}\n";
        let (_d, s, fake) = daemon(vec![ok, ok, ok]);
        let restart = Action::Restart { live_screen: true };
        let got = run(async move { act(&s, &restart, "dev").await });
        assert_eq!(got, Ok(serde_json::Value::Null));
        let ops: Vec<String> = fake
            .join()
            .unwrap()
            .iter()
            .map(|l| {
                serde_json::from_str::<serde_json::Value>(l).unwrap()["request"]["op"].to_string()
            })
            .collect();
        assert_eq!(ops, ["\"set_vnc\"", "\"stop\"", "\"start\""]);
        // A failed stop ends it: no start.
        let (_d, s, fake) = daemon(vec![ok, "{\"ok\":false,\"error\":\"dev is busy\"}\n"]);
        let restart = Action::Restart { live_screen: true };
        let got = run(async move { act(&s, &restart, "dev").await });
        // The stop, the second request.
        assert_eq!(got, Err((1, CallError::Failed("dev is busy".into()))));
        assert_eq!(fake.join().unwrap().len(), 2);
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
    fn lifecycle_passes_busy_snapshots() {
        // Every snapshot slot taken, e.g. by RAM snapshots of big VMs.
        let held = runtime()
            .block_on(SNAPS.acquire_many(SNAP_SLOTS as u32))
            .unwrap();
        let (_d, s, fake) = serve(
            r#"{"op":"stop","name":"dev","force":false}"#,
            answer("{\"ok\":true}\n"),
        );
        let stop = run(async move { act(&s, &Action::Life(Op::Stop), "dev").await });
        fake.join().unwrap();
        assert_eq!(stop, Ok(serde_json::Value::Null));
        let (_d, s, _) = serve(
            r#"{"op":"snapshot_delete","name":"dev","tag":"s1"}"#,
            answer("{\"ok\":true}\n"),
        );
        let queued = run(async move {
            let delete = Action::Delete("s1".into());
            tokio::time::timeout(Duration::from_millis(200), act(&s, &delete, "dev")).await
        });
        assert!(queued.is_err(), "snapshot actions still queue");
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
