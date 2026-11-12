//! The UI channel (`stallo set <vm> --ui on`): a second virtio-serial port
//! that the guest sees as `/dev/virtio-ports/org.stallo.ui.0` and the host
//! as `<runtime>/ui.sock`. Lines go both ways, a guest write blocks while
//! no host side is connected and leaves nothing for a later connection,
//! and the port follows the RAM snapshot rule of `set --net`.

mod common;

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use common::Daemon;

const PORT: &str = "/dev/virtio-ports/org.stallo.ui.0";

/// Opens the port once (a virtio port allows one opener), sends `hello`,
/// and writes the first line it reads to /root/got.
const ECHO: &str = "
import os
f = os.open('/dev/virtio-ports/org.stallo.ui.0', os.O_RDWR)
os.write(f, b'hello\\n')
got = b''
while not got.endswith(b'\\n'):
    got += os.read(f, 64)
open('/root/got', 'wb').write(got)
";

#[test]
#[ignore = "boots a VM; run with STALLO_IT=1"]
fn ui_channel() {
    if !common::enabled() {
        return;
    }
    let d = Daemon::start("ui", "");
    d.ok(&[
        "new", "ui", "--image", &d.image, "--cpus", "1", "--mem", "1G", "--disk", "10G",
    ]);
    // Through `ok`, so a failed exec never passes for a missing port.
    let has_port = |d: &Daemon| {
        let out = d.ok(&[
            "exec",
            "ui",
            "--",
            "sh",
            "-c",
            &format!("test -e {PORT} && echo yes || echo no"),
        ]);
        out.trim() == "yes"
    };
    // Off for a VM from a cloud image; refused while running.
    assert!(!has_port(&d));
    let out = d.stallo(&["set", "ui", "--ui", "on"]);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("stop it first"),
        "{out:?}"
    );
    d.ok(&["stop", "ui"]);
    d.ok(&["set", "ui", "--ui", "on"]);
    d.ok(&["start", "ui"]);
    d.assert_safe("ui");
    assert!(has_port(&d));
    let sock = d.vm_runtime("ui").join("ui.sock");
    assert!(sock.exists());

    // No host side yet: a guest write blocks (the helper must not wait on
    // it forever), and what it never sent does not reach a host that
    // connects later.
    let early = d.stallo(&[
        "exec",
        "ui",
        "--admin",
        "--",
        "timeout",
        "5",
        "sh",
        "-c",
        &format!("echo early > {PORT}"),
    ]);
    assert_eq!(early.status.code(), Some(124), "{early:?}");

    let conn = UnixStream::connect(&sock).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    d.ok(&[
        "exec",
        "ui",
        "--admin",
        "--",
        "systemd-run",
        "--unit=echo",
        "python3",
        "-I",
        "-c",
        ECHO,
    ]);
    let mut lines = BufReader::new(conn.try_clone().unwrap());
    let mut first = String::new();
    lines.read_line(&mut first).unwrap();
    assert_eq!(first, "hello\n", "a stale line reached the host");
    (&conn).write_all(b"pong\n").unwrap();
    let got = common::wait_for(Duration::from_secs(10), || {
        d.stallo(&["exec", "ui", "--admin", "--", "cat", "/root/got"])
            .stdout
            .starts_with(b"pong")
    });
    assert!(got.is_ok(), "the guest did not get the host's line");
    drop((lines, conn));

    // A RAM snapshot holds the port: it restores with it, and the port
    // cannot change while the snapshot exists.
    d.ok(&["snap", "ui", "s1"]);
    d.ok(&["restore", "ui", "s1"]);
    assert!(has_port(&d));
    // Also from a stopped VM.
    d.ok(&["stop", "ui"]);
    d.ok(&["restore", "ui", "s1"]);
    assert!(has_port(&d));
    d.ok(&["stop", "ui"]);
    let out = d.stallo(&["set", "ui", "--ui", "off"]);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("RAM snapshots (s1)"),
        "{out:?}"
    );
    d.ok(&["snap", "ui", "--delete", "s1", "--yes"]);
    d.ok(&["set", "ui", "--ui", "off"]);
    d.ok(&["start", "ui"]);
    assert!(!has_port(&d));
    assert!(!sock.exists());
    d.ok(&["stop", "ui"]);
    d.ok(&["rm", "ui", "--yes"]);
}
