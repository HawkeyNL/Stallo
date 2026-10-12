//! stallo: the command-line client for stallod.

use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result, bail, ensure};
use clap::{Parser, Subcommand};
use serde_json::Value;

use stallo::api::{self, Envelope, ExecResult, ImageInfo, NewResult, Request, Via, VmInfo};
use stallo::config::NetProfile;
use stallo::host::HostInfo;

#[derive(Parser)]
#[command(version, about = "Agent-first VMs on Ubuntu", propagate_version = true)]
struct Cli {
    /// Print machine-readable JSON.
    #[arg(long, global = true)]
    json: bool,
    /// API socket (default: $STALLO_SOCKET, else the dev-mode socket).
    #[arg(long, global = true)]
    socket: Option<PathBuf>,
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a VM, start it and wait until it is ready.
    New {
        #[arg(default_value = "dev")]
        name: String,
        #[arg(long, default_value = "ubuntu-26.04")]
        image: String,
        #[arg(long, default_value_t = 2)]
        cpus: u32,
        /// Memory, e.g. 2G or 1536M.
        #[arg(long, default_value = "2G", value_parser = parse_mib)]
        mem: u64,
        /// Disk size, e.g. 20G.
        #[arg(long, default_value = "20G", value_parser = parse_gib)]
        disk: u64,
        #[arg(long, value_enum, default_value = "offline")]
        net: Net,
        /// Return once QEMU runs, without waiting for the guest agent.
        #[arg(long)]
        no_wait: bool,
    },
    /// List VMs.
    Ls,
    /// Start a stopped VM and wait until it is ready.
    Start {
        vm: String,
        #[arg(long)]
        no_wait: bool,
    },
    /// Power a VM off (ACPI, then forced after 60 s).
    Stop {
        vm: String,
        /// Kill at once.
        #[arg(long)]
        force: bool,
    },
    /// Run a command in the guest; its exit code is passed through.
    Exec {
        vm: String,
        /// Run as root instead of the guest user.
        #[arg(long)]
        admin: bool,
        /// Seconds before the command is killed (default 120, max 3600).
        #[arg(long)]
        timeout: Option<u64>,
        #[arg(last = true, required = true)]
        argv: Vec<String>,
    },
    /// Continue a paused VM (for example after the disk watchdog paused it).
    Resume { vm: String },
    /// Show host resources and what VMs use.
    Host,
    /// Delete a stopped VM and all its files.
    Rm {
        vm: String,
        /// Do not ask.
        #[arg(long)]
        yes: bool,
    },
    /// Serve the agent tools over MCP on stdin/stdout.
    Mcp,
    /// List images, or download one.
    Images {
        #[command(subcommand)]
        action: Option<ImagesCmd>,
    },
}

#[derive(Subcommand)]
enum ImagesCmd {
    /// Download and verify an image.
    Pull { id: String },
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum Net {
    Offline,
    Internet,
}

/// Exit code for errors of stallo itself (daemon unreachable, no such VM,
/// timeout...), so they differ from a guest command's own exit code.
const STALLO_ERROR: u8 = 125;

fn main() -> ExitCode {
    let cli = Cli::parse();
    // stdout is the MCP channel for `stallo mcp`: errors go to stderr.
    let json = cli.json && !matches!(cli.command, Cmd::Mcp);
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => return fail(&e.into(), json),
    };
    match rt.block_on(run(cli)) {
        Ok(code) => code,
        Err(e) => fail(&e, json),
    }
}

fn fail(e: &anyhow::Error, json: bool) -> ExitCode {
    if json {
        println!(
            "{}",
            serde_json::json!({"ok": false, "error": format!("{e:#}")})
        );
    } else {
        eprintln!("stallo: {e:#}");
    }
    ExitCode::from(STALLO_ERROR)
}

async fn run(cli: Cli) -> Result<ExitCode> {
    let socket = match cli
        .socket
        .or_else(|| std::env::var_os("STALLO_SOCKET").map(PathBuf::from))
    {
        Some(s) => s,
        None => stallo::paths::Paths::dev()?.api_socket(),
    };
    let call = |request: Request| {
        let socket = socket.clone();
        async move {
            api::call(
                &socket,
                &Envelope {
                    via: Via::Cli,
                    request,
                },
            )
            .await
        }
    };
    let json = cli.json;
    let print_json = |v: &Value| println!("{}", serde_json::to_string_pretty(v).unwrap());

    match cli.command {
        Cmd::New {
            name,
            image,
            cpus,
            mem,
            disk,
            net,
            no_wait,
        } => {
            let net = match net {
                Net::Offline => NetProfile::Offline,
                Net::Internet => NetProfile::Internet,
            };
            let v = call(Request::New {
                name,
                image,
                vcpus: cpus,
                memory_mib: mem,
                disk_gib: disk,
                net,
                wait: !no_wait,
            })
            .await?;
            if json {
                print_json(&v);
            } else {
                let r: NewResult = serde_json::from_value(v)?;
                let when = match r.ready_ms {
                    Some(ms) => format!("ready in {:.0}s", ms as f64 / 1000.0),
                    None => "started".to_owned(),
                };
                println!("{}  {when}  {}", r.vm.name, summary(&r.vm));
            }
        }
        Cmd::Ls => {
            let v = call(Request::List).await?;
            if json {
                print_json(&v);
            } else {
                let vms: Vec<VmInfo> = serde_json::from_value(v)?;
                print_table(&vms);
            }
        }
        Cmd::Start { vm, no_wait } => {
            let v = call(Request::Start {
                name: vm.clone(),
                wait: !no_wait,
            })
            .await?;
            if json {
                print_json(&v);
            } else {
                println!("{vm}  started");
            }
        }
        Cmd::Stop { vm, force } => {
            call(Request::Stop {
                name: vm.clone(),
                force,
            })
            .await?;
            if !json {
                println!("{vm}  stopped");
            }
        }
        Cmd::Exec {
            vm,
            admin,
            timeout,
            argv,
        } => {
            let v = call(Request::Exec {
                name: vm,
                argv,
                admin,
                timeout_s: timeout,
            })
            .await?;
            let r: ExecResult = serde_json::from_value(v.clone())?;
            if json {
                print_json(&v);
            } else {
                std::io::stdout().write_all(r.stdout.as_bytes())?;
                std::io::stderr().write_all(r.stderr.as_bytes())?;
                if r.truncated {
                    eprintln!("stallo: output truncated");
                }
            }
            return Ok(ExitCode::from(u8::try_from(r.exit_code).unwrap_or(255)));
        }
        Cmd::Resume { vm } => {
            call(Request::Resume { name: vm.clone() }).await?;
            if !json {
                println!("{vm}  resumed");
            }
        }
        Cmd::Host => {
            let v = call(Request::Host).await?;
            if json {
                print_json(&v);
            } else {
                let h: HostInfo = serde_json::from_value(v)?;
                print!("{h}");
            }
        }
        Cmd::Rm { vm, yes } => {
            if !yes {
                confirm(&format!("Delete VM {vm} and all its files?"))?;
            }
            call(Request::Rm { name: vm.clone() }).await?;
            if !json {
                println!("{vm}  removed");
            }
        }
        Cmd::Mcp => stallo::mcp::serve_stdio(socket).await?,
        Cmd::Images { action } => {
            let request = match action {
                None => Request::Images,
                Some(ImagesCmd::Pull { id }) => Request::Pull { image: id },
            };
            let v = call(request).await?;
            if json {
                print_json(&v);
            } else {
                let images: Vec<ImageInfo> = serde_json::from_value(v)?;
                for i in images {
                    let state = if i.cached { "cached" } else { "not downloaded" };
                    println!("{:<16} {:<16} {}", i.id, state, i.name);
                }
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// `2 vCPU · 2 GiB · offline`
fn summary(vm: &VmInfo) -> String {
    format!(
        "{} vCPU · {} · {}",
        vm.vcpus,
        mib(vm.memory_mib),
        serde_json::to_value(vm.net)
            .unwrap()
            .as_str()
            .unwrap_or("?")
    )
}

fn mib(m: u64) -> String {
    if m.is_multiple_of(1024) {
        format!("{} GiB", m / 1024)
    } else {
        format!("{m} MiB")
    }
}

fn print_table(vms: &[VmInfo]) {
    if vms.is_empty() {
        println!("no VMs; create one with `stallo new`");
        return;
    }
    println!(
        "{:<20} {:<12} {:>4} {:>9} {:>6}  {:<8} AGENT",
        "NAME", "STATE", "CPUS", "MEMORY", "DISK", "NET"
    );
    for vm in vms {
        println!(
            "{:<20} {:<12} {:>4} {:>9} {:>5}G  {:<8} {}",
            vm.name,
            vm.state,
            vm.vcpus,
            mib(vm.memory_mib),
            vm.disk_gib,
            serde_json::to_value(vm.net)
                .unwrap()
                .as_str()
                .unwrap_or("?"),
            if vm.agent_control { "on" } else { "off" }
        );
    }
}

/// Asks on a terminal; refuses without one (scripts must pass `--yes`).
fn confirm(question: &str) -> Result<()> {
    if !std::io::stdin().is_terminal() {
        bail!("refusing to delete without a terminal; pass --yes");
    }
    eprint!("{question} [y/N] ");
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    if !matches!(answer.trim(), "y" | "Y" | "yes") {
        bail!("cancelled");
    }
    Ok(())
}

/// Parses `2G`, `1536M`, `512MiB` or a plain MiB count.
fn parse_mib(s: &str) -> Result<u64> {
    let s = s.trim();
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: u64 = num.parse().with_context(|| format!("invalid size {s:?}"))?;
    let factor = match unit.to_ascii_lowercase().as_str() {
        "" | "m" | "mb" | "mib" => 1,
        "g" | "gb" | "gib" => 1024,
        _ => bail!("invalid size {s:?}; use e.g. 2G or 1536M"),
    };
    n.checked_mul(factor).context("size too large")
}

/// Parses `20G`, `20GiB` or a plain GiB count.
fn parse_gib(s: &str) -> Result<u64> {
    let s = s.trim();
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    ensure!(
        matches!(unit.to_ascii_lowercase().as_str(), "" | "g" | "gb" | "gib"),
        "invalid size {s:?}; use e.g. 20G"
    );
    num.parse()
        .with_context(|| format!("invalid size {s:?}; use e.g. 20G"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(parse_mib("2G").unwrap(), 2048);
        assert_eq!(parse_mib("1536M").unwrap(), 1536);
        assert_eq!(parse_mib("512MiB").unwrap(), 512);
        assert_eq!(parse_mib("4gib").unwrap(), 4096);
        assert_eq!(parse_mib("300").unwrap(), 300);
        assert!(parse_mib("2T").is_err());
        assert!(parse_mib("G").is_err());
        assert!(parse_mib("-1G").is_err());
        assert_eq!(parse_gib("20G").unwrap(), 20);
        assert_eq!(parse_gib("20").unwrap(), 20);
        assert!(parse_gib("20M").is_err());
        assert!(parse_gib("20bib").is_err());
        assert!(parse_gib("20B").is_err());
        assert_eq!(parse_gib("20GiB").unwrap(), 20);
    }

    #[test]
    fn cli_parses() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
        let c = Cli::try_parse_from(["stallo", "exec", "dev", "--", "uname", "-a"]).unwrap();
        assert!(matches!(c.command, Cmd::Exec { ref argv, .. } if argv == &["uname", "-a"]));
    }
}
