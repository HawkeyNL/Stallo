//! GUI-8 gate: the app's RFB client against a real VM's VNC socket.
//!
//! The client lives in the GUI crate, which is a binary; it is compiled in
//! here as a module, so its own unit tests run here too.

mod common;

#[allow(dead_code)]
#[path = "../gui/src/rfb.rs"]
mod rfb;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

use common::Daemon;
use stallo::api::{Request, Via, VmDetails};

/// `a` on a PC keyboard: GTK keycode (evdev 30 + 8) and X keysym.
const KEY_A: (u32, u32) = (38, 0x61);

#[test]
#[ignore = "boots a VM; run with STALLO_IT=1"]
fn screen_over_vnc() {
    if !common::enabled() {
        return;
    }
    let d = Daemon::start("screen", "");
    let t = Instant::now();
    d.ok(&[
        "new", "dev", "--image", &d.image, "--cpus", "2", "--mem", "2G", "--disk", "20G",
    ]);
    eprintln!(
        "MEASURE create -> ready: {:.1} s",
        t.elapsed().as_secs_f64()
    );
    // From the next start, so stop and start once.
    d.ok(&["set", "dev", "--vnc", "on"]);
    let t = Instant::now();
    d.ok(&["stop", "dev"]);
    d.ok(&["start", "dev"]);
    eprintln!(
        "MEASURE restart with VNC -> ready: {:.1} s",
        t.elapsed().as_secs_f64()
    );
    d.assert_safe("dev");

    let info = d
        .api(Via::Cli, Request::Info { name: "dev".into() })
        .unwrap();
    let info: VmDetails = serde_json::from_value(info).unwrap();
    let socket = info.vnc_socket.expect("no VNC socket while running");
    // Dev mode: only this user.
    let mode = fs::metadata(&socket).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);

    // The guest's keyboard, read as root once the key below is sent.
    let reader = std::thread::scope(|scope| {
        let reader = scope.spawn(|| {
            d.ok(&[
                "exec",
                "dev",
                "--admin",
                "--",
                "sh",
                "-c",
                "timeout 30 head -c 24 /dev/input/by-path/platform-i8042-serio-0-event-kbd | od -An -tx1",
            ])
        });
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let t = Instant::now();
                let (session, mut frames) = rfb::Session::connect(&socket).await.unwrap();
                tokio::time::timeout(Duration::from_secs(10), frames.changed())
                    .await
                    .expect("no frame in 10 s")
                    .expect("the session ended");
                let first = frames.borrow_and_update().clone();
                eprintln!(
                    "MEASURE connect -> first frame: {} ms",
                    t.elapsed().as_millis()
                );
                assert_eq!((first.width, first.height), (1280, 800));
                assert_eq!(first.serial, 1);
                let mut px = first.pixels.chunks_exact(4).map(|p| &p[..3]);
                let one = px.next().unwrap();
                assert!(px.any(|p| p != one), "the first frame is all one colour");

                // Time for the reader to open the device.
                tokio::time::sleep(Duration::from_secs(5)).await;
                let (keycode, keysym) = KEY_A;
                for down in [true, false] {
                    session.send(rfb::Input::Key {
                        keycode,
                        keysym,
                        down,
                    });
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
                assert_eq!(session.end_reason(), None);
            });
        reader.join().unwrap()
    });
    // One input event (24 bytes) came in.
    assert_eq!(reader.split_whitespace().count(), 24, "{reader}");

    d.ok(&["stop", "dev"]);
    d.ok(&["rm", "dev", "--yes"]);
}
