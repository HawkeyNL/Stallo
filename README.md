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

Run the daemon in dev mode (being built in milestone M0). Dev mode runs as
your own user under your systemd user manager, with cgroup delegation so it
can set per-VM limits. Data lives
in `~/.local/share/stallo-dev/`, runtime files in
`$XDG_RUNTIME_DIR/stallo-dev/`, and only the `offline` network profile is
available.

```sh
cargo build --release
systemd-run --user --unit=stallod-dev -p Delegate=yes \
    "$PWD/target/release/stallod" --dev
```

Dev mode is not a security boundary against other processes of your own
user: they can reach the daemon socket just like `stallo` can.

## Licence

Licence: to be decided.
