//! M1 gate through the real MCP adapter: `stallo mcp` on stdio, driven by
//! a scripted MCP client the way Claude Code drives it.

mod common;

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::{Value, json};

use common::Daemon;

struct Mcp {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    id: u64,
}

impl Mcp {
    fn start(d: &Daemon) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_stallo"))
            .arg("--socket")
            .arg(&d.socket)
            .arg("mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let mut m = Self {
            child,
            stdin,
            stdout,
            id: 0,
        };
        let init = m.request(
            "initialize",
            json!({"protocolVersion": "2025-06-18", "capabilities": {},
                   "clientInfo": {"name": "kvm-test", "version": "0"}}),
        );
        assert_eq!(init["serverInfo"]["name"], "stallo");
        m.send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
        m
    }

    fn send(&mut self, msg: Value) {
        writeln!(self.stdin, "{msg}").unwrap();
    }

    /// Sends a request and returns its `result`; every stdout line must be
    /// JSON-RPC.
    fn request(&mut self, method: &str, params: Value) -> Value {
        self.id += 1;
        let id = self.id;
        self.send(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        loop {
            let mut line = String::new();
            assert!(
                self.stdout.read_line(&mut line).unwrap() > 0,
                "stallo mcp exited"
            );
            let msg: Value = serde_json::from_str(&line).expect("stdout is only JSON-RPC");
            if msg["id"] == id {
                return msg["result"].clone();
            }
        }
    }

    /// Calls a tool; panics on a tool error.
    fn tool(&mut self, name: &str, args: Value) -> Value {
        let r = self.request("tools/call", json!({"name": name, "arguments": args}));
        assert_eq!(r["isError"], false, "{name}: {r}");
        r
    }

    fn text(&mut self, name: &str, args: Value) -> Value {
        let r = self.tool(name, args);
        serde_json::from_str(r["content"][0]["text"].as_str().unwrap()).unwrap_or(Value::Null)
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
#[ignore = "boots a VM; run with STALLO_IT=1"]
fn agent_session_over_mcp() {
    if !common::enabled() {
        return;
    }
    let d = Daemon::start("mcp", "");
    d.ok(&["new", "dev", "--cpus", "2", "--mem", "2G", "--disk", "20G"]);
    d.assert_safe("dev");
    let mut m = Mcp::start(&d);

    // An opted-out VM refuses every tool.
    let r = m.request(
        "tools/call",
        json!({"name": "screenshot", "arguments": {"vm": "dev"}}),
    );
    assert_eq!(r["isError"], true);
    assert!(
        r["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("agent control is off")
    );
    d.ok(&["agent", "dev", "on"]);

    let list = m.text("vm_list", json!({}));
    assert_eq!(list["vms"][0]["agent_control"], true);
    let info = m.text("vm_info", json!({"vm": "dev"}));
    assert_eq!(info["state"], "running");
    assert!(
        info["addresses"].to_string().contains("127.0.0.1"),
        "{info}"
    );

    // The gate: work on the console with screenshot, key, type_text and
    // wait_for_screen only, and read the result.
    let shot = m.tool("screenshot", json!({"vm": "dev"}));
    assert_eq!(shot["content"][0]["type"], "image");
    assert_eq!(shot["content"][1]["text"], "1280x800");
    // Like an agent: let the console settle (login prints and flushes
    // typeahead), clear it, then type.
    m.tool("wait_for_screen", json!({"vm": "dev"}));
    m.tool("key", json!({"vm": "dev", "keys": "ctrl+l"}));
    m.tool(
        "type_text",
        json!({"vm": "dev", "text": "echo gate-$((6*7)) | tee /tmp/gate\n"}),
    );
    let settled = m.tool("wait_for_screen", json!({"vm": "dev", "stable_ms": 1000}));
    assert_eq!(settled["content"][0]["mimeType"], "image/png");
    if let Some(dir) = std::env::var_os("STALLO_IT_SHOTS") {
        use base64::Engine;
        let png = base64::engine::general_purpose::STANDARD
            .decode(settled["content"][0]["data"].as_str().unwrap())
            .unwrap();
        std::fs::write(std::path::Path::new(&dir).join("mcp-gate.png"), png).unwrap();
    }
    let gate = m.text("file_read", json!({"vm": "dev", "path": "/tmp/gate"}));
    assert_eq!(gate["text"], "gate-42\n");

    // File round trip and exec with an exit code.
    let note = "line one\nünïcode ✓\n";
    m.tool(
        "file_write",
        json!({"vm": "dev", "path": "/home/agent/note.txt", "data": note}),
    );
    let back = m.text(
        "file_read",
        json!({"vm": "dev", "path": "/home/agent/note.txt"}),
    );
    assert_eq!(back["text"], note);
    let out = m.text(
        "exec",
        json!({"vm": "dev", "argv": ["sh", "-c", "wc -l < /home/agent/note.txt; exit 3"]}),
    );
    assert_eq!(out["exit_code"], 3);
    assert_eq!(out["stdout"], "2\n");

    // Pointer tools answer too.
    let clicked = m.tool(
        "click",
        json!({"vm": "dev", "x": 5, "y": 5, "screenshot": true}),
    );
    assert_eq!(clicked["content"][0]["type"], "image");
    m.tool("scroll", json!({"vm": "dev", "x": 5, "y": 5, "dy": 1}));

    // A hard reset, and the guest comes back.
    m.tool("vm_reset", json!({"vm": "dev"}));
    m.tool("mouse_move", json!({"vm": "dev", "x": 100, "y": 100}));
    m.tool(
        "drag",
        json!({"vm": "dev", "from_x": 0, "from_y": 0, "to_x": 9, "to_y": 9}),
    );
    let mut back = false;
    for _ in 0..60 {
        let r = m.request(
            "tools/call",
            json!({"name": "exec", "arguments": {"vm": "dev", "argv": ["true"]}}),
        );
        if r["isError"] == false {
            back = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    assert!(back, "the guest agent did not come back after vm_reset");

    // Off again: refused.
    d.ok(&["agent", "dev", "off"]);
    let r = m.request(
        "tools/call",
        json!({"name": "exec", "arguments": {"vm": "dev", "argv": ["true"]}}),
    );
    assert_eq!(r["isError"], true);
    let audit = std::fs::read_to_string(d.data.join("audit/dev.jsonl")).unwrap();
    assert!(!audit.contains("gate-"), "typed text in the audit log");
    assert!(!audit.contains("ünïcode"));
}
