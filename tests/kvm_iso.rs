//! ISO-2 gate: a VM from an installer ISO boots the installer from its
//! CD-ROM drive. Needs `stallo images pull fedora-44-workstation` in dev
//! mode first (about 2.7 GB).
//!
//! The RFB client lives in the GUI crate; it is compiled in here as a
//! module, as in `kvm_screen.rs`.

mod common;

#[allow(dead_code)]
#[path = "../gui/src/rfb.rs"]
mod rfb;

use std::collections::HashSet;
use std::fs;
use std::time::{Duration, Instant};

use base64::Engine;
use common::Daemon;
use stallo::api::{Request, Via, VmDetails};
use stallo::config::VmConfig;

const ISO: &str = "fedora-44-workstation";
/// What `stallo new` gives an ISO VM by default.
const MEMORY_MIB: u64 = 4096;

#[test]
#[ignore = "boots a VM from an installer ISO; run with STALLO_IT=1"]
fn boots_installer_iso() {
    if !common::enabled() {
        return;
    }
    // Guest RAM, QEMU's overhead and slack, as in kvm_snapshot.rs.
    let need = MEMORY_MIB + 512 + common::HEADROOM_MIB;
    let available = Daemon::host_available_mib();
    assert!(
        available >= need,
        "{available} MiB available, {need} MiB needed"
    );
    let d = Daemon::start_with("iso", "", MEMORY_MIB, ISO);
    // The ISO defaults (2 vCPUs, 4 GiB, 32 GiB); no guest agent to wait for.
    let t = Instant::now();
    let out = d.ok(&["new", "desk", "--image", ISO]);
    assert!(out.contains("started"), "{out}");
    eprintln!(
        "MEASURE create -> started: {:.1} s",
        t.elapsed().as_secs_f64()
    );
    d.assert_safe("desk");

    // A blank disk and the ISO in the drive; no seed, no password, VNC on.
    let cfg = VmConfig::load(&d.vm_dir("desk")).unwrap();
    assert_eq!(
        (
            cfg.cdrom.as_deref(),
            cfg.vnc,
            cfg.vcpus,
            cfg.memory_mib,
            cfg.disk_gib
        ),
        (Some(ISO), true, 2, MEMORY_MIB, 32)
    );
    for f in ["seed.iso", "seed", "secret"] {
        assert!(!d.vm_dir("desk").join(f).exists(), "{f}");
    }
    let qemu = d.vm_pids("desk")[0];
    let argv = fs::read_to_string(format!("/proc/{qemu}/cmdline"))
        .unwrap()
        .replace('\0', " ");
    assert!(
        argv.contains("-blockdev driver=raw,node-name=cd0,file=cd0-file,read-only=on")
            && argv.contains("-device ide-cd,id=cd0,drive=cd0,bus=ide.0,bootindex=2")
            && !argv.contains("seed"),
        "{argv}"
    );

    // The installer reads its kernel, initrd and root image from the CD.
    // QEMU's own reads stand in for cd0's rd_bytes (the daemon holds the
    // only QMP connection): the disk is blank and the firmware is 4 MiB.
    let read = || -> u64 {
        let io = fs::read_to_string(format!("/proc/{qemu}/io")).unwrap();
        io.lines()
            .find_map(|l| l.strip_prefix("rchar: "))
            .unwrap()
            .parse()
            .unwrap()
    };
    let booted = common::wait_for(Duration::from_secs(480), || read() > 100 << 20);
    eprintln!("MEASURE QEMU read {} MiB", read() >> 20);
    let booted = booted.expect("the guest read less than 100 MiB from its CD in 8 minutes");
    eprintln!(
        "MEASURE start -> 100 MiB read: {:.1} s",
        booted.as_secs_f64()
    );

    // Then the live desktop, over VNC: past the boot splash (a black screen
    // with two logos), most of the screen is lit and in many colours.
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
    let socket = info.vnc_socket.expect("no VNC socket while running");
    let look = || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let (_session, mut frames) = rfb::Session::connect(&socket).await.unwrap();
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
    };
    let mut seen = (0, 0);
    let shown = common::wait_for(Duration::from_secs(420), || {
        seen = look();
        seen.0 >= 256 && seen.1 >= 25 || {
            std::thread::sleep(Duration::from_secs(5));
            false
        }
    });
    // Kept next to the test data for a human to look at.
    let shot = d
        .api(
            Via::Cli,
            Request::Screenshot {
                name: "desk".into(),
            },
        )
        .unwrap();
    let png = base64::engine::general_purpose::STANDARD
        .decode(shot["png_base64"].as_str().unwrap())
        .unwrap();
    let saved = d.base.parent().unwrap().join("iso-installer.png");
    fs::write(&saved, &png).unwrap();
    eprintln!(
        "MEASURE screen: {} colours, {}% lit; saved {}",
        seen.0,
        seen.1,
        saved.display()
    );
    let shown = shown.expect("the screen stayed (nearly) blank");
    eprintln!(
        "MEASURE 100 MiB read -> desktop: {:.1} s",
        shown.as_secs_f64()
    );

    d.assert_safe("desk");
    d.ok(&["stop", "desk", "--force"]);
    d.ok(&["rm", "desk", "--yes"]);
    // The cached ISO is the human's to delete.
    assert!(d.data.join(format!("images/{ISO}.iso")).is_file());
}
