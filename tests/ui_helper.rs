//! The guest UI helper's own checks (role and state mapping, requests, a
//! walk over a fake accessibility tree), when the host has python3.

use std::process::Command;

#[test]
fn helper_self_test() {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/guest/stallo-ui.py");
    let Ok(out) = Command::new("python3")
        .args(["-I", script, "--self-test"])
        .output()
    else {
        eprintln!("no python3: skipped");
        return;
    };
    assert!(
        out.status.success() && out.stdout == b"ok\n",
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
