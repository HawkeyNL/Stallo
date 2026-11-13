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
use stallo::api::{Request, Via};
use stallo::ui::Action;

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

/// A stand-in for the real helper: answers `hello` and `tree` with the
/// `small.json` fixture (`small-after.json` once /root/switch exists),
/// `probe` with the node's bbox and the screen (every node hit but `a3`),
/// and `focus` and `invoke` with ok. In `hostile` mode it answers `tree`
/// with a 2 MiB line and junk but never a reply. Touches /root/<unit>.ready once it
/// holds the port.
const FAKE_HELPER: &str = r#"
import json, os, sys, time
mode = sys.argv[1]
tree = json.load(open('/root/tree.json'))
after = json.load(open('/root/after.json'))
f = os.open('/dev/virtio-ports/org.stallo.ui.0', os.O_RDWR)
open('/root/' + sys.argv[2] + '.ready', 'w').close()
def send(b):
    while b:
        b = b[os.write(f, b):]
buf = b''
while True:
    chunk = os.read(f, 65536)
    if not chunk:
        time.sleep(0.1)
        continue
    buf += chunk
    while b'\n' in buf:
        line, buf = buf.split(b'\n', 1)
        req = json.loads(line)
        if req['op'] == 'hello':
            out = {'id': req['id'], 'ok': True, 'v': 1}
        elif mode == 'hostile':
            send(b'x' * (2 << 20) + b'\njunk\n')
            continue
        elif req['op'] == 'tree':
            t = after if os.path.exists('/root/switch') else tree
            out = {'id': req['id'], 'ok': True, 'tree': t}
        elif req['op'] == 'probe':
            node = [n for n in tree['nodes'] if n['key'] == req['key']][0]
            out = {'id': req['id'], 'ok': True, 'bbox': node.get('bbox'), 'hit': req['key'] != 'a3',
                   'screen': tree['screen']}
        else:
            out = {'id': req['id'], 'ok': True}
        send((json.dumps(out) + '\n').encode())
"#;

/// `stallo ui` through the channel, against a fake helper in the guest: a
/// missing or hostile helper is a clean error, and a restored RAM snapshot
/// starts the ids over.
#[test]
#[ignore = "boots a VM; run with STALLO_IT=1"]
fn ui_tree_from_a_helper() {
    if !common::enabled() {
        return;
    }
    let d = Daemon::start("uitree", "");
    d.ok(&[
        "new", "ui", "--image", &d.image, "--cpus", "1", "--mem", "1G", "--disk", "10G",
    ]);
    d.ok(&["stop", "ui"]);
    d.ok(&["set", "ui", "--ui", "on"]);
    d.ok(&["start", "ui"]);
    d.assert_safe("ui");
    let ui = |args: &[&str]| d.stallo(&[&["ui", "ui"], args].concat());
    let stderr = |o: &std::process::Output| String::from_utf8_lossy(&o.stderr).into_owned();
    let tmp = tempfile::tempdir().unwrap();

    let out = ui(&[]);
    assert!(
        stderr(&out).contains("no UI helper answered in ui"),
        "{out:?}"
    );

    // The install: refused without Python's AT-SPI bindings, before any
    // file is written; with them (a stand-in `gi` here) all three files
    // land and udev reloads.
    let has = |path: &str| {
        let out = d.ok(&[
            "exec",
            "ui",
            "--",
            "sh",
            "-c",
            &format!("test -e {path} && echo yes || echo no"),
        ]);
        out.trim() == "yes"
    };
    let out = ui(&["--install"]);
    assert!(
        stderr(&out).contains("lacks Python's AT-SPI bindings"),
        "{out:?}"
    );
    assert!(!has("/usr/local/lib/stallo-ui"));
    let site = d.ok(&[
        "exec",
        "ui",
        "--",
        "python3",
        "-I",
        "-c",
        "import sys; print([p for p in sys.path if p.startswith('/usr/local/lib/python3')][0])",
    ]);
    let gi = format!("{}/gi", site.trim());
    d.ok(&[
        "exec",
        "ui",
        "--admin",
        "--",
        "mkdir",
        "-p",
        &format!("{gi}/repository"),
    ]);
    let fake = tmp.path().join("gi.py");
    std::fs::write(&fake, "def require_version(name, version):\n    pass\n").unwrap();
    d.ok(&[
        "cp",
        "--admin",
        fake.to_str().unwrap(),
        &format!("ui:{gi}/__init__.py"),
    ]);
    std::fs::write(&fake, "Atspi = None\n").unwrap();
    d.ok(&[
        "cp",
        "--admin",
        fake.to_str().unwrap(),
        &format!("ui:{gi}/repository/__init__.py"),
    ]);
    let out = d.ok(&["ui", "ui", "--install"]);
    assert!(out.contains("installed the UI helper in ui"), "{out}");
    for path in [
        "/usr/local/lib/stallo-ui/stallo-ui.py",
        "/etc/xdg/autostart/stallo-ui.desktop",
        "/etc/udev/rules.d/70-stallo-ui.rules",
    ] {
        assert!(has(path), "{path}");
    }
    let helper = d.ok(&[
        "exec",
        "ui",
        "--",
        "python3",
        "-I",
        "/usr/local/lib/stallo-ui/stallo-ui.py",
        "--self-test",
    ]);
    assert_eq!(helper, "ok\n");

    let script = tmp.path().join("fakeui.py");
    std::fs::write(&script, FAKE_HELPER).unwrap();
    let fixture = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/ui/small.json");
    d.ok(&["cp", "--admin", fixture, "ui:/root/tree.json"]);
    let after = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/ui/small-after.json"
    );
    d.ok(&["cp", "--admin", after, "ui:/root/after.json"]);
    d.ok(&[
        "cp",
        "--admin",
        script.to_str().unwrap(),
        "ui:/root/fakeui.py",
    ]);
    let helper = |unit: &str, mode: &str| {
        d.ok(&[
            "exec",
            "ui",
            "--admin",
            "--",
            "systemd-run",
            &format!("--unit={unit}"),
            "python3",
            "-I",
            "/root/fakeui.py",
            mode,
            unit,
        ]);
        let ready = format!("/root/{unit}.ready");
        let up = common::wait_for(Duration::from_secs(20), || {
            d.stallo(&["exec", "ui", "--admin", "--", "test", "-e", &ready])
                .status
                .success()
        });
        assert!(up.is_ok(), "{unit} never opened the port");
    };
    let stop = |unit: &str| d.ok(&["exec", "ui", "--admin", "--", "systemctl", "stop", unit]);

    helper("fakeui1", "normal");
    let up = common::wait_for(Duration::from_secs(20), || ui(&[]).status.success());
    assert!(up.is_ok(), "the fake helper never answered");
    let t = std::time::Instant::now();
    let first = d.ok(&["ui", "ui"]);
    eprintln!(
        "MEASURE stallo ui round trip: {} ms",
        t.elapsed().as_millis()
    );
    assert!(
        first.contains("\ne1 window \"Files — Home\" (nautilus) active\n"),
        "{first}"
    );
    let found = d.ok(&["ui", "ui", "--find", "agent@"]);
    assert!(found.contains("text \"agent@dev:~$\""), "{found}");

    // A hostile helper: an error, and the next helper works again.
    stop("fakeui1");
    helper("fakeui2", "hostile");
    // Over the kept connection: the junk is skipped until the time limit.
    let out = ui(&[]);
    assert!(
        stderr(&out).contains("the UI helper did not answer within 5s"),
        "{out:?}"
    );
    stop("fakeui2");
    helper("fakeui3", "normal");
    let up = common::wait_for(Duration::from_secs(20), || ui(&[]).status.success());
    assert!(up.is_ok(), "no answer after the hostile helper");
    let again = d.ok(&["ui", "ui"]);
    assert_eq!(
        again.split_once('\n').unwrap().1,
        first.split_once('\n').unwrap().1
    );

    // Acting by id: a click reaches QMP only where the helper's hit test
    // finds the control.
    let act = |action, id: &str| {
        let r = d.api(
            Via::Cli,
            Request::UiAct {
                name: "ui".into(),
                action,
                id: Some(id.into()),
                text: None,
                keys: None,
                dy: None,
                settle_ms: Some(0),
                until: None,
            },
        );
        r.map(|v| v["text"].as_str().unwrap().to_owned())
    };
    let out = act(Action::Click, "e2").unwrap();
    assert!(out.starts_with("clicked e2 at 26,56\n"), "{out}");
    let e = act(Action::Click, "e3").unwrap_err().to_string();
    assert!(e.contains("e3 is covered by something else"), "{e}");
    assert!(
        act(Action::Invoke, "e6")
            .unwrap()
            .starts_with("invoked e6\n")
    );
    // A dialog opens in the guest two seconds later.
    d.ok(&[
        "exec",
        "ui",
        "--admin",
        "--",
        "systemd-run",
        "--on-active=2",
        "touch",
        "/root/switch",
    ]);
    let waited = d
        .api(
            Via::Cli,
            Request::UiWait {
                name: "ui".into(),
                until: "Save As".into(),
                gone: false,
                timeout_ms: Some(20_000),
            },
        )
        .unwrap();
    let waited = waited["text"].as_str().unwrap();
    assert!(waited.starts_with("matched after "), "{waited}");
    assert!(
        waited.contains(" window \"Save As\" (gedit) active"),
        "{waited}"
    );

    // The guest went back: its ids start over.
    d.ok(&["snap", "ui", "s1"]);
    d.ok(&["restore", "ui", "s1"]);
    let restored = d.ok(&["ui", "ui"]);
    assert!(restored.contains("; seq 1;"), "{restored}");
    d.ok(&["stop", "ui"]);
    d.ok(&["snap", "ui", "--delete", "s1", "--yes"]);
    d.ok(&["rm", "ui", "--yes"]);
}
