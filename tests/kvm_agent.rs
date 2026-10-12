//! M1 gate: an agent drives an offline VM through the daemon API that
//! `stallo mcp` uses.

mod common;

use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use stallo::api::{Request, ScreenResult, Via};

use common::Daemon;

#[test]
#[ignore = "boots a VM; run with STALLO_IT=1"]
fn agent_drives_the_console() {
    if !common::enabled() {
        return;
    }
    let d = Daemon::start("agent", "");
    d.ok(&["new", "dev", "--cpus", "2", "--mem", "2G", "--disk", "20G"]);
    d.assert_safe("dev");
    let call = |r: Request| d.api(Via::Cli, r).unwrap();
    let screen = |r: Request| -> (ScreenResult, Vec<u8>) {
        let s: ScreenResult = serde_json::from_value(call(r)).unwrap();
        let png = BASE64.decode(&s.png_base64).unwrap();
        (s, png)
    };

    // Screenshot: a 1280x800 PNG, timed.
    let mut times = Vec::new();
    for _ in 0..20 {
        let t = Instant::now();
        let (s, png) = screen(Request::Screenshot { name: "dev".into() });
        times.push(t.elapsed());
        assert_eq!((s.width, s.height), (1280, 800));
        assert!(png.starts_with(b"\x89PNG"));
    }
    eprintln!(
        "MEASURE screenshot p50 {:?} p95 {:?}",
        pct(&mut times, 50),
        pct(&mut times, 95)
    );

    // The idle console settles.
    let t = Instant::now();
    let (s, png) = screen(Request::WaitForScreen {
        name: "dev".into(),
        stable_ms: Some(1000),
        timeout_ms: Some(30000),
    });
    assert_eq!(s.stable, Some(true));
    eprintln!(
        "MEASURE wait_for_screen (idle, 1 s stable): {:?}",
        t.elapsed()
    );
    save(&png, "idle");

    // The console logged in by itself: type a command on it.
    let text: String = (' '..='~').collect();
    let t = Instant::now();
    call(Request::TypeText {
        name: "dev".into(),
        text: "cat > /tmp/typed\n".into(),
    });
    call(Request::TypeText {
        name: "dev".into(),
        text: format!("{text}\n"),
    });
    call(Request::Key {
        name: "dev".into(),
        keys: "ctrl+d".into(),
    });
    let typed = 17 + text.len() + 1;
    eprintln!("MEASURE type_text: {typed} characters in {:?}", t.elapsed());
    let (_, png) = screen(Request::WaitForScreen {
        name: "dev".into(),
        stable_ms: Some(500),
        timeout_ms: Some(10000),
    });
    save(&png, "typed");
    let out = d.ok(&["exec", "dev", "--", "cat", "/tmp/typed"]);
    assert_eq!(
        out,
        format!("{text}\n"),
        "every printable character arrives"
    );
    let owner = d.ok(&["exec", "dev", "--", "stat", "-c", "%U", "/tmp/typed"]);
    assert_eq!(owner.trim(), "agent", "the console is the agent user");

    // Pointer events reach the guest's tablet as sent: read its evdev node
    // while clicking and scrolling.
    let events = std::thread::scope(|scope| {
        let reader = scope.spawn(|| {
            d.ok(&[
                "exec", "dev", "--admin", "--", "sh", "-c",
                "ev=$(awk '/Virtio Tablet/{f=1} f && /^H:/{for(i=1;i<=NF;i++) if($i ~ /^event/) print $i; exit}' /proc/bus/input/devices); \
                 timeout 3 cat /dev/input/$ev | od -An -v -tx1 -w24; true",
            ])
        });
        std::thread::sleep(Duration::from_millis(1500));
        call(Request::Click {
            name: "dev".into(),
            x: 640,
            y: 400,
            button: None,
            double: false,
            screenshot: false,
        });
        call(Request::Scroll {
            name: "dev".into(),
            x: 640,
            y: 400,
            dy: -2,
        });
        reader.join().unwrap()
    });
    let events: Vec<(u16, u16, i32)> = events
        .lines()
        .filter_map(|l| {
            let b: Vec<u8> = l
                .split_whitespace()
                .map(|h| u8::from_str_radix(h, 16).unwrap())
                .collect();
            (b.len() == 24).then(|| {
                (
                    u16::from_le_bytes([b[16], b[17]]),
                    u16::from_le_bytes([b[18], b[19]]),
                    i32::from_le_bytes([b[20], b[21], b[22], b[23]]),
                )
            })
        })
        .collect();
    let (x, y) = (
        stallo::input::abs_axis(640, 1280).unwrap() as i32,
        stallo::input::abs_axis(400, 800).unwrap() as i32,
    );
    for want in [(3, 0, x), (3, 1, y), (1, 0x110, 1), (1, 0x110, 0)] {
        assert!(events.contains(&want), "{want:?} not in {events:?}");
    }
    let wheel_up = events.iter().filter(|e| **e == (2, 8, 1)).count();
    assert_eq!(wheel_up, 2, "{events:?}");

    // Pointer: moves, clicks (with a screenshot), drags and scrolls work;
    // off-screen coordinates are refused.
    call(Request::MouseMove {
        name: "dev".into(),
        x: 640,
        y: 400,
    });
    let mut times = Vec::new();
    for _ in 0..10 {
        let t = Instant::now();
        let v = call(Request::Click {
            name: "dev".into(),
            x: 10,
            y: 10,
            button: None,
            double: false,
            screenshot: true,
        });
        times.push(t.elapsed());
        let s: ScreenResult = serde_json::from_value(v).unwrap();
        assert_eq!(s.width, 1280);
    }
    eprintln!(
        "MEASURE click + screenshot p50 {:?} p95 {:?}",
        pct(&mut times, 50),
        pct(&mut times, 95)
    );
    call(Request::Drag {
        name: "dev".into(),
        from_x: 0,
        from_y: 0,
        to_x: 1279,
        to_y: 799,
    });
    call(Request::Scroll {
        name: "dev".into(),
        x: 5,
        y: 5,
        dy: -3,
    });
    for bad in [
        Request::MouseMove {
            name: "dev".into(),
            x: 1280,
            y: 0,
        },
        Request::Drag {
            name: "dev".into(),
            from_x: 0,
            from_y: 0,
            to_x: 0,
            to_y: 800,
        },
        Request::Scroll {
            name: "dev".into(),
            x: 0,
            y: 0,
            dy: 0,
        },
        Request::TypeText {
            name: "dev".into(),
            text: "café".into(),
        },
        Request::Key {
            name: "dev".into(),
            keys: "ctrl+hyper".into(),
        },
    ] {
        assert!(d.api(Via::Cli, bad).is_err());
    }

    // A screen that keeps changing does not settle: the guest prints a
    // line every 100 ms on the console for 4 s.
    let writer = std::thread::scope(|scope| {
        let h = scope.spawn(|| {
            d.ok(&[
                "exec",
                "dev",
                "--admin",
                "--",
                "sh",
                "-c",
                "for i in $(seq 40); do echo line $i > /dev/tty1; sleep 0.1; done",
            ])
        });
        std::thread::sleep(Duration::from_millis(500));
        let (s, _) = screen(Request::WaitForScreen {
            name: "dev".into(),
            stable_ms: Some(1000),
            timeout_ms: Some(2500),
        });
        h.join().unwrap();
        s.stable
    });
    assert_eq!(writer, Some(false));

    // Files: a 9 MiB binary file goes in and comes back (stallo cp, in
    // parts both ways), owned by the guest user; reads take an offset.
    let dir = tempfile::tempdir().unwrap();
    let blob: Vec<u8> = (0..9u32 << 20)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    let (src, back) = (dir.path().join("blob"), dir.path().join("back"));
    std::fs::write(&src, &blob).unwrap();
    let t = Instant::now();
    d.ok(&["cp", src.to_str().unwrap(), "dev:/home/agent/blob"]);
    eprintln!("MEASURE cp 9 MiB host -> guest: {:?}", t.elapsed());
    let t = Instant::now();
    d.ok(&["cp", "dev:/home/agent/blob", back.to_str().unwrap()]);
    eprintln!("MEASURE cp 9 MiB guest -> host: {:?}", t.elapsed());
    assert!(std::fs::read(&back).unwrap() == blob, "round trip differs");
    let owner = d.ok(&["exec", "dev", "--", "stat", "-c", "%U", "/home/agent/blob"]);
    assert_eq!(owner.trim(), "agent");
    let part: stallo::api::FileData = serde_json::from_value(call(Request::FileRead {
        name: "dev".into(),
        path: "/home/agent/blob".into(),
        offset: 1000,
        max_bytes: Some(10),
        admin: false,
    }))
    .unwrap();
    assert_eq!(BASE64.decode(&part.data_base64).unwrap(), blob[1000..1010]);
    assert!(part.more);
    let past_end: stallo::api::FileData = serde_json::from_value(call(Request::FileRead {
        name: "dev".into(),
        path: "/home/agent/blob".into(),
        offset: 10 << 20,
        max_bytes: None,
        admin: false,
    }))
    .unwrap();
    assert_eq!((past_end.size, past_end.more), (0, false));
    // A guest directory as the target keeps the host file name.
    d.ok(&["cp", src.to_str().unwrap(), "dev:/tmp/"]);
    assert_eq!(
        d.ok(&["exec", "dev", "--", "stat", "-c", "%s", "/tmp/blob"])
            .trim(),
        (9u32 << 20).to_string()
    );
    // An empty file is copied too.
    std::fs::write(&src, b"").unwrap();
    d.ok(&["cp", src.to_str().unwrap(), "dev:/tmp/empty"]);
    assert_eq!(
        d.ok(&["exec", "dev", "--", "stat", "-c", "%s", "/tmp/empty"])
            .trim(),
        "0"
    );

    // The guest user's permissions apply unless admin.
    let read = |path: &str, admin: bool| {
        d.api(
            Via::Cli,
            Request::FileRead {
                name: "dev".into(),
                path: path.into(),
                offset: 0,
                max_bytes: None,
                admin,
            },
        )
    };
    let err = read("/etc/shadow", false).unwrap_err().to_string();
    assert!(err.contains("Permission denied"), "{err}");
    assert!(read("/etc/shadow", true).is_ok());
    assert!(read("/nonexistent", true).is_err());
    assert!(read("relative", true).is_err());
    let write = |path: &str, admin: bool| {
        d.api(
            Via::Cli,
            Request::FileWrite {
                name: "dev".into(),
                path: path.into(),
                data_base64: BASE64.encode(b"x"),
                append: false,
                admin,
            },
        )
    };
    assert!(write("/etc/stallo-test", false).is_err());
    assert!(write("/etc/stallo-test", true).is_ok());

    // exec passes stdin.
    let v = call(Request::Exec {
        name: "dev".into(),
        argv: vec!["cat".into()],
        admin: false,
        timeout_s: None,
        stdin: Some("from stdin".into()),
    });
    assert_eq!(v["stdout"], "from stdin");

    // Bad arguments are refused.
    for (stable_ms, timeout_ms) in [(10, 1000), (2000, 1000), (1000, 300_001)] {
        let bad = d.api(
            Via::Cli,
            Request::WaitForScreen {
                name: "dev".into(),
                stable_ms: Some(stable_ms),
                timeout_ms: Some(timeout_ms),
            },
        );
        assert!(bad.is_err(), "{stable_ms} {timeout_ms}");
    }
    assert!(
        d.api(
            Via::Cli,
            Request::Screenshot {
                name: "nope".into()
            }
        )
        .is_err()
    );
}

/// The `p`th percentile.
fn pct(times: &mut [Duration], p: usize) -> Duration {
    times.sort();
    times[(times.len() * p / 100).min(times.len() - 1)]
}

/// Keeps a screenshot for a human when `STALLO_IT_SHOTS` names a directory.
fn save(png: &[u8], name: &str) {
    if let Some(dir) = std::env::var_os("STALLO_IT_SHOTS") {
        std::fs::write(std::path::Path::new(&dir).join(format!("{name}.png")), png).unwrap();
    }
}
