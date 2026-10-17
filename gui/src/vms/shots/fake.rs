//! A fake stallod and a fake VM screen for the screenshot harness: fixed
//! answers on Unix sockets, no daemon, no VMs.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

/// The fake VNC socket, relative to the working directory like the rest.
pub const VNC_SOCKET: &str = "vnc.sock";

/// A few VMs in different states.
pub fn vms() -> Value {
    json!([
        vm("dev", "running", "ubuntu-26.04", true, true),
        vm("win11", "running", "local-win11", false, true),
        vm("build", "paused", "debian-13", false, false),
        vm("fedora", "stopped", "fedora-44", false, true),
        vm("desk", "stopped", "fedora-44-workstation", false, false),
    ])
}

fn vm(name: &str, state: &str, image: &str, agent: bool, vnc: bool) -> Value {
    let mut vm = json!({
        "name": name, "state": state, "vcpus": 4, "memory_mib": 8192,
        "disk_gib": 40, "net": "internet", "agent_control": agent, "vnc": vnc,
        "image": image,
    });
    if name == "dev" {
        vm["forwards"] = json!([{"bind": "127.0.0.1", "host": 8080, "guest": 80}]);
    }
    if image.starts_with("local-") {
        vm["cdrom"] = json!(image);
    }
    vm
}

fn info(vms: &Value, name: &str) -> Option<Value> {
    let mut vm = vms.as_array()?.iter().find(|v| v["name"] == name)?.clone();
    let running = vm["state"] != "stopped";
    vm["addresses"] = if running {
        json!([["enp0s2", "10.0.2.15/24"]])
    } else {
        json!([])
    };
    vm["disk_used_bytes"] = json!(7_340_032_000_u64);
    if running && vm["vnc"] == true {
        vm["vnc_socket"] = json!(VNC_SOCKET);
    }
    Some(vm)
}

fn host() -> Value {
    json!({
        "cores": 16, "vcpus_allotted": 8, "memory_total_mib": 32000,
        "memory_available_mib": 18000, "memory_budget_mib": 24000,
        "memory_used_mib": 17400, "disk_free_bytes": 412_000_000_000_u64,
        "disk_floor_gib": 20, "running_vms": 3,
    })
}

/// `desk` has no RAM snapshots, so its Internet Access switch can move.
fn snapshots(vm: &str) -> Value {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let mut all = json!([
        {"name": "clean-install", "ram_bytes": 0, "created": now - 9 * 86_400, "vm_clock_ms": 0},
        {"name": "before-upgrade", "ram_bytes": 8_589_934_592_u64, "created": now - 26 * 3600, "vm_clock_ms": 5_400_000},
        {"name": "snapshot-3", "ram_bytes": 0, "created": now - 600, "vm_clock_ms": 0},
    ]);
    if vm == "desk" {
        all.as_array_mut().unwrap().retain(|s| s["ram_bytes"] == 0);
    }
    all
}

/// Catalog images, downloaded or not, and an imported Windows ISO.
fn images() -> Value {
    json!([
        {"id": "ubuntu-26.04", "name": "Ubuntu 26.04 LTS server (cloud image)", "cached": true,
         "kind": "cloud-image", "os": "linux", "size_bytes": 650_000_000_u64},
        {"id": "debian-13", "name": "Debian 13 (trixie) generic cloud image (20261015-2632)",
         "cached": false, "kind": "cloud-image", "os": "linux"},
        {"id": "ubuntu-26.04-desktop", "name": "Ubuntu 26.04.1 LTS Desktop (installer ISO)",
         "cached": true, "kind": "iso", "os": "linux", "size_bytes": 6_200_000_000_u64},
        {"id": "local-win11", "name": "Windows 11 24H2 (imported ISO)", "cached": true,
         "kind": "iso", "os": "windows", "size_bytes": 5_800_000_000_u64},
    ])
}

/// Answers stallod's read requests from `vms` on `socket` until the
/// process ends. Anything else gets an error.
pub fn daemon(socket: &Path, vms: Value) -> std::io::Result<()> {
    let listener = UnixListener::bind(socket)?;
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let _ = answer(stream, &vms);
        }
    });
    Ok(())
}

fn answer(stream: UnixStream, vms: &Value) -> std::io::Result<()> {
    let mut line = String::new();
    BufReader::new(&stream).read_line(&mut line)?;
    let request: Value = serde_json::from_str(&line).unwrap_or_default();
    let request = &request["request"];
    let data = match request["op"].as_str().unwrap_or_default() {
        "list" => Some(vms.clone()),
        "host" => Some(host()),
        "info" => info(vms, request["name"].as_str().unwrap_or_default()),
        "snapshots" => Some(snapshots(request["name"].as_str().unwrap_or_default())),
        "images" => Some(images()),
        _ => None,
    };
    let reply = match data {
        Some(data) => json!({"ok": true, "data": data}),
        None => json!({"ok": false, "error": "not in the screenshot harness"}),
    };
    (&stream).write_all(format!("{reply}\n").as_bytes())
}

const WIDTH: u16 = 1280;
const HEIGHT: u16 = 800;

/// An RFB 3.8 server that sends one placeholder frame, then idles.
pub fn screen(socket: &Path) -> std::io::Result<()> {
    let listener = UnixListener::bind(socket)?;
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || serve_screen(stream));
        }
    });
    Ok(())
}

fn serve_screen(mut s: UnixStream) -> std::io::Result<()> {
    let mut buf = [0; 12];
    s.write_all(b"RFB 003.008\n")?;
    s.read_exact(&mut buf)?;
    s.write_all(&[1, 1])?; // one security type: None
    s.read_exact(&mut buf[..1])?;
    s.write_all(&[0; 4])?; // SecurityResult: OK
    s.read_exact(&mut buf[..1])?; // ClientInit
    let mut init = Vec::new();
    init.extend_from_slice(&WIDTH.to_be_bytes());
    init.extend_from_slice(&HEIGHT.to_be_bytes());
    init.extend_from_slice(&[0; 16]); // the client sets its own format
    init.extend_from_slice(&0u32.to_be_bytes());
    s.write_all(&init)?;
    let mut update = vec![0, 0, 0, 1, 0, 0, 0, 0];
    update.extend_from_slice(&WIDTH.to_be_bytes());
    update.extend_from_slice(&HEIGHT.to_be_bytes());
    update.extend_from_slice(&0i32.to_be_bytes()); // Raw
    update.extend_from_slice(&placeholder());
    s.write_all(&update)?;
    // Drain the client's requests and input until it hangs up.
    std::io::copy(&mut s, &mut std::io::sink())?;
    Ok(())
}

/// A calm desktop: a vertical gradient with a panel and a window, as
/// B G R x pixels.
fn placeholder() -> Vec<u8> {
    let (w, h) = (usize::from(WIDTH), usize::from(HEIGHT));
    let mut px = Vec::with_capacity(w * h * 4);
    for y in 0..h {
        for x in 0..w {
            let t = (y * 255 / h) as u8;
            let (r, g, b) = if y < 28 {
                (30, 30, 34)
            } else if (240..1040).contains(&x) && (160..640).contains(&y) {
                if y < 196 {
                    (235, 235, 238)
                } else {
                    (250, 250, 250)
                }
            } else {
                (40 + t / 3, 70 + t / 4, 140 - t / 3)
            };
            px.extend_from_slice(&[b, g, r, 0]);
        }
    }
    px
}
