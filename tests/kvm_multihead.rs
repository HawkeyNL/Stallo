//! Multiple screens: a VM from an installer ISO with 2 screens shows the
//! live desktop on both, through screenshots and VNC per screen. Needs
//! `stallo images pull fedora-44-workstation` in dev mode first.
//!
//! The RFB client lives in the GUI crate; it is compiled in here as a
//! module, as in `kvm_screen.rs`.

mod common;

#[allow(dead_code)]
#[path = "../gui/src/rfb.rs"]
mod rfb;

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::time::Duration;

use common::Daemon;
use stallo::api::{Request, ScreenResult, Via, VmDetails};

const ISO: &str = "fedora-44-workstation";
const MEMORY_MIB: u64 = 4096;

/// Colours and the lit share (percent) of one VNC frame of `socket`.
fn look(socket: &Path) -> (usize, usize) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let (_session, mut frames) = rfb::Session::connect(socket).await.unwrap();
            tokio::time::timeout(Duration::from_secs(10), frames.changed())
                .await
                .expect("no frame in 10 s")
                .expect("the session ended");
            let frame = frames.borrow_and_update().clone();
            assert_eq!((frame.width, frame.height), (1280, 800));
            let px = || frame.pixels.chunks_exact(4).map(|p| [p[0], p[1], p[2]]);
            let colours = px().collect::<HashSet<_>>().len();
            let lit = px().filter(|p| p.iter().any(|&c| c > 48)).count();
            (colours, lit * 100 / px().count())
        })
}

fn argv(d: &Daemon) -> String {
    let qemu = d.vm_pids("desk")[0];
    fs::read_to_string(format!("/proc/{qemu}/cmdline"))
        .unwrap()
        .replace('\0', " ")
}

#[test]
#[ignore = "boots a VM from an installer ISO; run with STALLO_IT=1"]
fn two_screens() {
    if !common::enabled() {
        return;
    }
    let need = MEMORY_MIB + 512 + common::HEADROOM_MIB;
    let available = Daemon::host_available_mib();
    assert!(
        available >= need,
        "{available} MiB available, {need} MiB needed"
    );
    let d = Daemon::start_with("mh", "", MEMORY_MIB, ISO);
    d.ok(&["new", "desk", "--image", ISO]);
    let out = d.stallo(&["set", "desk", "--screens", "2"]);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("stop it first"),
        "{out:?}"
    );
    d.ok(&["stop", "desk", "--force"]);
    let out = d.ok(&["set", "desk", "--screens", "2"]);
    assert!(out.contains("desk  screens 2"), "{out}");
    d.ok(&["start", "desk"]);
    d.assert_safe("desk");
    let a = argv(&d);
    for i in 0..2 {
        assert!(
            a.contains(&format!(
                "-device virtio-gpu-pci,id=video{i},max_outputs=1,edid=on,xres=1280,yres=800,max_hostmem=64M"
            )),
            "{a}"
        );
    }
    assert!(!a.contains("bochs-display") && !a.contains("tcp:"), "{a}");

    let info: VmDetails = serde_json::from_value(
        d.api(
            Via::Cli,
            Request::Info {
                name: "desk".into(),
            },
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(info.vm.screens, 2);
    assert_eq!(info.vnc_sockets.len(), 2);
    assert!(info.vnc_sockets[1].ends_with("vnc-2.sock"));

    // GNOME extends its desktop onto screen 2: lit and in many colours.
    let mut seen = (0, 0);
    let shown = common::wait_for(Duration::from_secs(480), || {
        seen = look(&info.vnc_sockets[1]);
        seen.0 >= 256 && seen.1 >= 25 || {
            std::thread::sleep(Duration::from_secs(5));
            false
        }
    });
    assert!(shown.is_ok(), "screen 2 never showed the desktop: {seen:?}");

    // One screenshot holds both screens.
    let shot: ScreenResult = serde_json::from_value(
        d.api(
            Via::Cli,
            Request::Screenshot {
                name: "desk".into(),
            },
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!((shot.width, shot.height), (1280, 800));
    assert_eq!(shot.more.len(), 1);
    assert_eq!((shot.more[0].width, shot.more[0].height), (1280, 800));
    assert_ne!(shot.png_base64, shot.more[0].png_base64);

    let out = d.stallo(&["set", "desk", "--screens", "3"]);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("stop it first"),
        "{out:?}"
    );
    // Back to one screen: bochs-display as before.
    d.ok(&["stop", "desk", "--force"]);
    d.ok(&["set", "desk", "--screens", "1"]);
    d.ok(&["start", "desk"]);
    let a = argv(&d);
    assert!(
        a.contains("-device bochs-display") && !a.contains("virtio-gpu"),
        "{a}"
    );
    d.ok(&["stop", "desk", "--force"]);
}
