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
| `fedora-44` | Fedora 44 Cloud Base Generic (44-1.7) | The guest agent's SELinux domain is made permissive (see `catalog/fedora-44.toml`). Offline only for now. |
| `arch` | Arch Linux cloud image (arch-boxes) | No Secure Boot (its boot loader is not signed for it). Rolling: `latest/` moves every two weeks, and the first pull is kept. Offline only for now. |
| `debian-13` | Debian 13 generic cloud image (20261015-2632) | Pinned (upstream unsigned): Debian signs no checksums for its cloud images, so Stallo checks a SHA-512 built into it, and a newer build needs a Stallo release. So does a new Debian archive key: the archive keyring that checks the guest-agent package is vendored, and fetches fail until a release ships the new one. Offline only for now. |
| `ubuntu-26.04-desktop` | Ubuntu 26.04.1 LTS Desktop installer ISO (about 6 GB) | You install it on the VM's screen; no guest agent until you install one. Defaults: 2 vCPUs, 4 GiB, 32 GiB disk. Pinned to the point release: the next one needs a catalog bump. Offline only for now. |
| `fedora-44-workstation` | Fedora 44 Workstation live installer ISO (44-1.7, about 2.7 GB) | You install it on the VM's screen; no guest agent until you install one (its SELinux domain then needs to be permissive). Defaults: 2 vCPUs, 4 GiB, 32 GiB disk. Offline only for now. |

Use another one with `stallo new dev --image fedora-44` after pulling it.

The installer ISOs (`ubuntu-26.04-desktop`, `fedora-44-workstation`) give a
desktop that you install yourself on the VM's screen; see
[Install a desktop from an ISO](#install-a-desktop-from-an-iso).
Ubuntu images are checked with the host's Ubuntu keyrings; other
distributions' signing keys ship with Stallo in `catalog/keys/`. Ubuntu's
`current/` and Arch's `latest/` move to each new build, so their signatures
must be recent (Ubuntu's checksum list at most 90 days old, Arch's image at
most 45): a stale or replaying mirror cannot hold back an old build for
longer. Arch signs the image itself rather than a checksum list. Debian's image has no signature at all: its SHA-512 is pinned in the
catalog (`catalog/debian-13.toml`), while its guest-agent package comes
from the signed Debian archive. The `internet` profile is refused for
images it was not verified with (`internet` in the catalog entry): so far
the Ubuntu ones.

A pull starts only if the image's filesystem keeps the disk floor
(`disk_floor_gib`) free plus twice the image's largest size, or once for
an installer ISO, which is kept as downloaded (less what an interrupted
download already holds). A pulled image is kept as it is, and
`stallo images` shows the date of the signature it was verified with. To
get a newer build, or to free the space, delete it and pull again:

```sh
stallo images rm ubuntu-26.04   # refused while any VM was made from it
stallo images pull ubuntu-26.04
```

What the package installs, and how to remove it: [docs/production.md](docs/production.md).

To give a VM more (or fewer) CPUs or memory, stop it first; the new size is
checked against the host like `stallo new` and applies from the next start:

```sh
stallo stop dev
stallo set dev --cpus 4 --mem 4G
stallo start dev
```

A VM with RAM snapshots keeps its size until they are deleted (a RAM
snapshot only restores into a VM of the size it was taken at). Disks
cannot be grown yet.

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
table with its loader unit. `packaging/build-gui-deb.sh` builds
`stallo-gui`, the desktop app (an early preview). Members of group `stallo` use the API
socket `/run/stallo/api.sock`, which the CLI picks by default when it
exists.
Install steps, rollback and the lab gate are in
[docs/production.md](docs/production.md).

Every push to `main` (channel `edge`) and every release tag (channel
`stable`) is published as a signed APT repository at
`https://hawkeynl.github.io/Stallo/`. Setup and key handling are in
[docs/apt-repo.md](docs/apt-repo.md).

## Viewing a VM's screen

`stallo set <vm> --vnc on` gives the VM a VNC server from its next start
(`stallo new <vm> --vnc` from its first),
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

## Install a desktop from an ISO

An installer ISO gives you a full desktop that you install yourself on
the VM's screen, as on a real PC. Stallo only boots the installer: there
is no seed, no cloud-init and no guest password, and the VM is offline.

1. Pull the ISO (humans only). Fedora's is about 2.7 GB, Ubuntu's about
   6 GB. A pull needs the disk floor plus the ISO's largest size free:

   ```sh
   stallo images pull fedora-44-workstation
   ```

2. Create the VM. It gets a blank 32 GiB disk, 2 vCPUs, 4 GiB, the ISO in
   a read-only CD-ROM drive and VNC. Change the size with `--cpus`,
   `--mem` and `--disk`. `new` returns once QEMU runs; nothing waits for
   a guest agent:

   ```sh
   stallo new desk --image fedora-44-workstation
   ```

3. Open the screen: the **Screen** tab in the desktop app, or a VNC
   viewer on `/run/stallo/vnc/desk/vnc.sock` in production (see
   [Viewing a VM's screen](#viewing-a-vms-screen)).
4. Install as usual. The installer sees only the VM's blank disk, never
   the host's. The desktop has no 3D acceleration, so it is slower than
   on hardware.
5. Eject the installer, then restart. The disk boots first, so the
   installed system starts even with the ISO still in; ejecting it means
   QEMU no longer reads the ISO:

   ```sh
   stallo set desk --cdrom eject       # from the next start
   stallo stop desk && stallo start desk
   ```

   `stallo set desk --cdrom fedora-44-workstation` puts it back, for
   example to repair the installed system.

The screen, keyboard and mouse work without anything in the guest. File
copies (`stallo cp`) and commands (`stallo exec`) need the QEMU guest
agent in the guest, which Stallo does not install. The VM is offline for
now, so the package must come from the installed system or its ISO:

- Check `systemctl status qemu-guest-agent`; if it is missing, install the
  `qemu-guest-agent` package, then
  `sudo systemctl enable --now qemu-guest-agent`.
- Without `--admin`, Stallo runs commands and file copies as the guest
  user `agent`. Create that user (`sudo useradd -m agent`), or use
  `--admin` (root) for every call.
- Fedora: SELinux confines the guest agent (`virt_qemu_ga_t`) and refuses
  what `exec` needs. Make only that domain permissive, as Stallo does for
  its Fedora cloud image:
  `echo '(typepermissive virt_qemu_ga_t)' > /tmp/qga.cil && sudo semodule -i /tmp/qga.cil`.

Stallo does not wait for a guest agent in a VM made from an ISO: not at
`new`, `start` or snapshot restore, even after you install one. Agents
may not create such VMs or change their CD-ROM drive. With agent control
on (`stallo agent desk on`) they may use the screen, keyboard and mouse,
and also files and commands once the guest agent runs.

Disk space: the cached ISO stays until you remove it
(`stallo images rm fedora-44-workstation`, refused while a VM has it in
its drive). The VM's disk grows as you install, up to its full size, and
each RAM snapshot of it takes up to its memory size.

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
