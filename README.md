# Stallo

Agent-first VM manager for Ubuntu, written in Rust on QEMU/KVM.

Stallo gives humans a simple way to run virtual machines and gives AI agents
full control of a VM over MCP: screen, keyboard, mouse, commands, files and
snapshots. Security and performance come first; guests are treated as
hostile.

Status: early development. Ubuntu 26.04 LTS hosts only.

## How it fits together

- `stallod` is the daemon. It is the only process that talks to QEMU (QMP),
  to the guest agent (QGA), to cgroups and to disk images. It never listens
  on TCP.
- `stallo` is the CLI. It sends newline-delimited JSON requests to the daemon
  over a Unix socket.
- Each VM runs as one `qemu-system-x86_64` process in its own cgroup
  (`vm-<name>`) with CPU, memory and process limits.

## Requirements

- Ubuntu 26.04 LTS on x86_64 with `/dev/kvm`; your user in group `kvm`.
- `qemu-system-x86`, `qemu-utils`, `ovmf`, `xorriso`, `curl`, `gpgv` and
  `ubuntu-cloudimage-keyring`.
- A Rust toolchain (pinned in `rust-toolchain.toml`).

## Development

Build and test:

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

KVM integration tests boot real, offline VMs (one at a time, at most
2 vCPUs and 2 GiB each; the snapshot pause measurement also uses one 4 GiB
guest, only while the host keeps 6 GiB available besides) and are skipped
unless asked for. They need the
Ubuntu 26.04 image in the dev-mode cache (`stallo images pull ubuntu-26.04`)
and run the daemon as a transient `systemd-run --user` unit:

```sh
STALLO_IT=1 cargo test -- --ignored --test-threads=1
```

Add `--nocapture` to see the `MEASURE` lines (boot time, screenshot,
click and exec latency, daemon memory); `tests/kvm_perf.rs` collects them.

Run the daemon in dev mode (being built in milestone M0). Dev mode runs as
your own user under your systemd user manager, with cgroup delegation so it
can set per-VM limits. Data lives
in `~/.local/share/stallo-dev/`, runtime files in
`$XDG_RUNTIME_DIR/stallo-dev/`, and only the `offline` network profile is
available.

```sh
cargo build --release
systemd-run --user --unit=stallod-dev -p Delegate=yes -p CPUWeight=50 \
    "$PWD/target/release/stallod" --dev
```

`CPUWeight=50` makes VMs yield CPU to other services under contention.

Dev mode is not a security boundary against other processes of your own
user: they can reach the daemon socket just like `stallo` can.

## Agents (MCP)

`stallo mcp` is an MCP server on stdin/stdout. Register it with Claude Code
for your user:

```sh
stallo mcp install    # runs `claude mcp add --scope user stallo -- <stallo> mcp`
```

Without `claude` on `PATH` it prints the JSON for other MCP clients.
Agents may only control VMs where you turned agent control on:

```sh
stallo agent dev on
```

Tools: `vm_list`, `vm_info`, `vm_create` (only with `agents_can_create =
true` in `stallod.toml`), `vm_start`, `vm_stop`, `vm_reset`, `screenshot`,
`wait_for_screen`, `mouse_move`, `click`, `drag`, `scroll`, `type_text`,
`key`, `exec`, `file_read`, `file_write`. There is no delete tool. Every
call is logged in `<data>/audit/`; see SECURITY.md.

## Licence

Licence: to be decided.
