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

Known limitation: in dev mode the daemon runs as the developer's own user, so
it is no boundary against other processes of that user. Production mode runs
the daemon as a dedicated `stallo` user.
