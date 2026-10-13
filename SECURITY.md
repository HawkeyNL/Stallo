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
