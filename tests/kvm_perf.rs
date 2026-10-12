//! Performance numbers for plan §7, printed as `MEASURE` lines. Generous
//! bounds only catch regressions by an order of magnitude; the numbers go
//! in the PR.

mod common;

use std::time::{Duration, Instant};

use stallo::api::{Request, Via};

use common::Daemon;

#[test]
#[ignore = "boots a VM; run with STALLO_IT=1"]
fn perf() {
    if !common::enabled() {
        return;
    }
    let d = Daemon::start("perf", "");
    let t = Instant::now();
    d.ok(&["new", "dev", "--cpus", "2", "--mem", "2G", "--disk", "20G"]);
    let ready = t.elapsed();
    d.assert_safe("dev");
    d.ok(&["agent", "dev", "on"]);
    let call = |r: Request| d.api(Via::Mcp, r).unwrap();

    let screenshot = timed(50, || {
        call(Request::Screenshot { name: "dev".into() });
    });
    let click = timed(20, || {
        call(Request::Click {
            name: "dev".into(),
            x: 5,
            y: 5,
            button: None,
            double: false,
            screenshot: true,
        });
    });
    let exec = timed(30, || {
        let v = call(Request::Exec {
            name: "dev".into(),
            argv: vec!["true".into()],
            admin: false,
            timeout_s: None,
            stdin: None,
        });
        assert_eq!(v["exit_code"], 0);
    });
    let exec_admin = timed(30, || {
        let v = call(Request::Exec {
            name: "dev".into(),
            argv: vec!["true".into()],
            admin: true,
            timeout_s: None,
            stdin: None,
        });
        assert_eq!(v["exit_code"], 0);
    });

    // Daemon at rest: resident memory and CPU time over 10 s with a
    // running VM and no requests.
    let pid = d.daemon_pid();
    let cpu = || {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
        let fields: Vec<u64> = stat
            .rsplit(')')
            .next()
            .unwrap()
            .split_whitespace()
            .skip(11)
            .take(2)
            .map(|f| f.parse().unwrap())
            .collect();
        fields[0] + fields[1]
    };
    let before = cpu();
    std::thread::sleep(Duration::from_secs(10));
    // USER_HZ is 100 on Linux: one tick is 10 ms.
    let idle_cpu_ms = (cpu() - before) * 10;
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    let rss_kib: u64 = status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .unwrap()
        .trim()
        .trim_end_matches(" kB")
        .parse()
        .unwrap();

    eprintln!(
        "MEASURE create -> guest agent ready: {:.1} s (target <= 45 s)",
        ready.as_secs_f64()
    );
    eprintln!(
        "MEASURE screenshot: {} (target p95 <= 150 ms)",
        summary(&screenshot)
    );
    eprintln!(
        "MEASURE click + screenshot: {} (target <= 200 ms)",
        summary(&click)
    );
    eprintln!("MEASURE exec true: {} (target <= 100 ms)", summary(&exec));
    eprintln!("MEASURE exec --admin true: {}", summary(&exec_admin));
    eprintln!(
        "MEASURE daemon idle RSS: {} MiB (target <= 20 MB)",
        rss_kib >> 10
    );
    eprintln!("MEASURE daemon idle CPU: {idle_cpu_ms} ms in 10 s (target ~0)");

    assert!(ready < Duration::from_secs(120));
    assert!(pct(&screenshot, 95) < Duration::from_millis(1500));
    assert!(pct(&exec, 50) < Duration::from_secs(1));
    assert!(rss_kib < 200 << 10);
}

fn timed(n: usize, mut f: impl FnMut()) -> Vec<Duration> {
    let mut times: Vec<Duration> = (0..n)
        .map(|_| {
            let t = Instant::now();
            f();
            t.elapsed()
        })
        .collect();
    times.sort();
    times
}

fn pct(sorted: &[Duration], p: usize) -> Duration {
    sorted[(sorted.len() * p / 100).min(sorted.len() - 1)]
}

fn summary(sorted: &[Duration]) -> String {
    let ms = |d: Duration| d.as_secs_f64() * 1000.0;
    format!(
        "p50 {:.0} ms, p95 {:.0} ms, max {:.0} ms (n={})",
        ms(pct(sorted, 50)),
        ms(pct(sorted, 95)),
        ms(sorted[sorted.len() - 1]),
        sorted.len()
    )
}
