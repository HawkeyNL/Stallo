# Security policy

Stallo runs untrusted guests next to other services, so security reports are
welcome.

## Reporting a vulnerability

Please do not open a public issue. Use GitHub's private vulnerability
reporting for this repository ("Security" tab, "Report a vulnerability").
You will get an answer within a week.

## Supported versions

Stallo is in early development. Only the latest commit on `main` is
supported.

## Scope

In scope: anything that lets a guest, an agent (over MCP) or another local
user reach further than the security model allows, for example the host, the
daemon's QMP/QGA sockets, other VMs, host files, or the host network.

Each QEMU process confines itself before it starts, without root
(`src/confine.rs`): a Landlock ruleset limits it to its own disk files, its
own runtime directory, the read-only base image and the system files and
devices QEMU needs, with no TCP; a seccomp filter blocks `connect`, every
socket other than a Unix stream socket, io_uring, changing file modes,
owners or extended attributes, resource limits and I/O priority of other
processes, and the user's keyrings. A guest that escapes
into QEMU therefore cannot open other VMs' disks or sockets, the daemon's
socket, cgroup files or the user's home. VMs do not start on kernels
without Landlock ABI 6 (Linux 6.12).

In production, QEMU also runs under the AppArmor profile `stallo-qemu`
(`packaging/apparmor/`): Stallo's own files only, no network, no
capabilities. The daemon checks QEMU's label before the guest's CPUs
start and every 10 s after, and kills a VM that is not confined by it.
The profile is shared by all VMs; keeping one VM's QEMU away from
another's stays the job of Landlock and seccomp.

## Remote MCP

`stallo mcp --http <ip>:<port>` serves the agent tools over HTTP. It is a
client of the daemon like stdio `stallo mcp` (every call `via: mcp`, same
agent policy) and runs with the API access of the user who starts it; the
daemon still has no IP listener. Before any request body is read:

- the listening address was checked: loopback or Tailscale only, never a
  wildcard or a LAN address;
- the peer must be of the same kind as the listening address: Linux also
  delivers LAN packets that are addressed to the Tailscale IP, and those
  connections are closed unanswered;
- at most 8 connections, 4 per peer address, with a 3 s header timeout;
- the bearer token is compared as SHA-256 digests in constant time; the
  token file must be a private regular file of the user (no symlink);
- authenticated requests get 20 per second; failed ones have a separate
  budget of 5 per second, so junk cannot starve the agent and tokens
  cannot be guessed quickly.

rmcp refuses `Host` headers other than the listening address (DNS
rebinding) and every request with an `Origin` header (browsers). Sessions
are not kept (stateless), so there is no session table to fill. Each
request is logged to stderr with the peer's address. Anyone who can reach
the port can still use up the connection slots: Tailscale ACLs are the
real boundary. Anyone with the token can do what agents may do; keep the
file private and rotate it by restarting with a new one.

## Agent policy

Agents reach Stallo through `stallo mcp`, which marks its requests
`via: mcp`. The daemon then refuses every tool on a VM whose agent
control is off (the default; `stallo agent <vm> on` turns it on), refuses
VM creation unless `agents_can_create = true` in `stallod.toml`, and
never lets agents delete VMs, pull images, resume VMs or change agent
control. Turning agent control off stops new agent calls; calls already
running (an `exec` can run up to an hour) finish first.

`via` is declared by the client. This is policy for well-behaved agents,
not a boundary: any process that can reach the API socket (in dev mode,
every process of the developer's user) can send CLI requests or run
`stallo agent <vm> on` itself. The boundaries are the socket permissions
and, in production, the separate `stallo` user.

In production the API socket is `/run/stallo/api.sock`, mode `0660`, group
`stallo`, and the daemon also checks the peer's groups (`SO_PEERGROUPS`).
VNC (`stallo set <vm> --vnc on`) listens only on a Unix socket in
`/run/stallo/vnc/<vm>/` (`0660`, group `stallo`; dev mode `0600`), never
on TCP, and has no password: the socket permissions are the boundary.
Keyboard and mouse input over VNC is not audited and ignores agent
control, so agents cannot turn VNC on. Once it is on, though, any process
of any group member can connect to the socket, an agent with a shell
included: turn VNC on only while you use it. QEMU's Landlock ruleset gains only
that directory (create and remove sockets).

Every member of group `stallo` has the full API, the same as the owner:
add only trusted users, and agents only through `stallo mcp`.

Every API call is logged, one JSON line each, in
`<data>/audit/<vm>.jsonl` (or `_daemon.jsonl` for calls that name no
existing VM): time, peer UID and PID, `via`, operation, argument sizes,
`argv[0]` for exec, result size, duration and ok/error. Never typed text,
file data, file paths, exec arguments after `argv[0]`, stdin or error
messages. Logs rotate at 10 MiB (three kept) and outlive `stallo rm`. An
agent call that cannot be logged is refused.

Known limitation: in dev mode the daemon runs as the developer's own user, so
it is no boundary against other processes of that user. Production mode runs
the daemon as a dedicated `stallo` user.
