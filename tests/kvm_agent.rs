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
