# Stallo

Agent-first VM manager for Ubuntu, written in Rust on QEMU/KVM.

Stallo gives humans a simple way to run virtual machines and gives AI agents
full control of a VM over MCP: screen, keyboard, mouse, commands, files and
snapshots. Security and performance come first; guests are treated as
hostile.

> **Alpha.** Stallo is early alpha software: expect bugs and breaking
> changes, and do not use it for anything you cannot afford to lose.
> Ubuntu 26.04 LTS on x86_64 only.

## Install

You need Ubuntu 26.04 LTS on x86_64 with hardware virtualisation (KVM)
turned on in the firmware. Add the signed APT repository and install the
package:

```sh
sudo install -d -m 0755 /etc/apt/keyrings
sudo curl -fsSLo /etc/apt/keyrings/stallo.asc https://hawkeynl.github.io/Stallo/stallo.asc
gpg --show-keys /etc/apt/keyrings/stallo.asc
```

Check that the fingerprint `gpg` prints is
`9C7434157F7D36A0E9B7A2000F3A4FCAC86F5A22`. If it differs, stop and
remove the file. Then:

```sh
sudo tee /etc/apt/sources.list.d/stallo.sources >/dev/null <<'EOF'
Types: deb
URIs: https://hawkeynl.github.io/Stallo/
Suites: edge
Components: main
Architectures: amd64
Signed-By: /etc/apt/keyrings/stallo.asc
EOF
sudo apt update && sudo apt install stallo
```

- `edge` gets a new build on every change to `main`. There is no `stable`
  release yet.
- Update with `sudo apt update && sudo apt upgrade`. An upgrade restarts
  the daemon, and that **stops every running VM**.

The package creates the system user `stallo` and starts `stallod`. To use
the `stallo` command, add yourself to group `stallo` and log out and in
again. Every member of this group has full control over all VMs, so add
only trusted users.

```sh
sudo usermod -aG stallo "$USER"
```

Your first VM:

```sh
stallo images pull ubuntu-26.04
stallo new dev
stallo exec dev -- uname -a
stallo ls
```

Guest images (`stallo images` lists them):

| ID | Image | Notes |
|---|---|---|
| `ubuntu-26.04` (default) | Ubuntu 26.04 LTS server cloud image | |
| `ubuntu-24.04` | Ubuntu 24.04 LTS server cloud image | |
| `fedora-44` | Fedora 44 Cloud Base Generic (44-1.7) | The guest agent's SELinux domain is made permissive (see `catalog/fedora-44.toml`). |

Use another one with `stallo new dev --image fedora-44` after pulling it.
Ubuntu images are checked with the host's Ubuntu keyrings; other
distributions' signing keys ship with Stallo in `catalog/keys/`.

What the package installs, and how to remove it: [docs/production.md](docs/production.md).

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
- `qemu-system-x86`, `qemu-utils`, `ovmf`, `xorriso`, `curl`, `gpgv`,
  `ubuntu-cloudimage-keyring` and `ubuntu-keyring`.
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

They use `ubuntu-26.04`; set `STALLO_IT_IMAGE_ID` (for example
`fedora-44`, pulled in dev mode first) to run them on another catalog image.

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

## Network profiles

- `offline` (the default): no network device at all.
- `internet`: the guest reaches the internet and nothing else. It cannot
  reach the host's own addresses, private and shared ranges (the LAN,
  Tailscale), link-local or multicast.
  - A LAN with global IPv6 addresses, or a router that answers on its
    public address, needs the extra steps in the install notes.
  - passt gives the guest its network; an nftables table on the host
    (`packaging/stallo.nft`) drops every connection the `stallo` user
    opens to those ranges.
  - Guest DNS goes to a public resolver (`[net] dns` in `stallod.toml`,
    default `9.9.9.9`).
  - Optional TCP port forwards: host ports above 1024, on `127.0.0.1`
    unless `--bind` names one host address:

    ```sh
    stallo new web --net internet --forward 8080:80
    ```

The `internet` profile needs production mode (`stallod` without `--dev`,
as user `stallo`), passt and the table. Without them the daemon refuses it
(`isolation unavailable`), and dev mode always refuses it.
- The daemon checks the table before every start and every 0.5 s while
  such VMs run.
- If the table is gone, it kills their passt at once. The guests keep
  running without network until they restart. The lab results and the host install steps are
in [docs/network-verification.md](docs/network-verification.md).

## Production mode

`packaging/build-deb.sh` builds a `.deb`. It installs `stallod.service`
(user `stallo`, hardened: `systemd-analyze security` 2.3) and the network
table with its loader unit. Members of group `stallo` use the API socket
`/run/stallo/api.sock`, which the CLI picks by default when it exists.
Install steps, rollback and the lab gate are in
[docs/production.md](docs/production.md).

Every push to `main` (channel `edge`) and every release tag (channel
`stable`) is published as a signed APT repository at
`https://hawkeynl.github.io/Stallo/`. Setup and key handling are in
[docs/apt-repo.md](docs/apt-repo.md).

## Viewing a VM's screen

`stallo set <vm> --vnc on` gives the VM a VNC server from its next start,
on a Unix socket only (never TCP): `<runtime>/vnc/<vm>/vnc.sock`, in
production `/run/stallo/vnc/<vm>/vnc.sock`, for members of group
`stallo`. From another machine, forward it over SSH. VNC has no password
here, so keep the forward private to you:

```sh
# Best, if your viewer takes a Unix socket: a socket only you can reach.
ssh -N -L "$XDG_RUNTIME_DIR/stallo-vnc.sock:/run/stallo/vnc/<vm>/vnc.sock" <host>
# Otherwise a loopback port; every local user of this machine can use it
# while the tunnel runs, so close it afterwards (never add -g).
ssh -N -L 127.0.0.1:5901:/run/stallo/vnc/<vm>/vnc.sock <host>
```

VNC input bypasses agent control and the audit log, so only humans can
turn it on. `stallo set <vm> --vnc off` removes it at the next start.

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

**Remote agents** (another machine on your tailnet) can use the same
tools over streamable HTTP. It runs as your user, never in the daemon:

```sh
mkdir -p ~/.config/stallo
(umask 077; head -c 32 /dev/urandom | base64 > ~/.config/stallo/mcp-token)
stallo mcp --http 100.101.102.103:8765 --token-file ~/.config/stallo/mcp-token
```

- Only loopback or a Tailscale address (`100.64.0.0/10`,
  `fd7a:115c:a1e0::/48`) is accepted; `0.0.0.0` and LAN addresses are
  refused, and so are peers from other networks. There is no TLS:
  Tailscale encrypts.
- Clients send `Authorization: Bearer <token>` and use the IP address in
  the URL: other `Host` names (MagicDNS too) and any browser `Origin` are
  refused. The token file must be yours and private (`0600`), at least 32
  characters.
- At most 20 authenticated requests per second, 5 failed ones, 8
  connections, 4 per peer. Each request is logged to stderr with the
  peer's address (never the token).
- Anyone who can reach the port can use up the connection slots, so let
  your Tailscale ACLs allow only the agent's machine.
- To keep it running: `systemd-run --user --unit=stallo-mcp-http stallo mcp --http ...`.

Tools: `vm_list`, `vm_info`, `vm_create` (only with `agents_can_create =
true` in `stallod.toml`), `vm_start`, `vm_stop`, `vm_reset`, `screenshot`,
`wait_for_screen`, `mouse_move`, `click`, `drag`, `scroll`, `type_text`,
`key`, `exec`, `file_read`, `file_write`, `image_list`. There is no
delete tool. Every call is logged in `<data>/audit/`; see SECURITY.md.

## Licence

Proprietary, all rights reserved; see [LICENSE](LICENSE).
