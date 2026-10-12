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

Known limitation: in dev mode the daemon runs as the developer's own user, so
it is no boundary against other processes of that user. Production mode runs
the daemon as a dedicated `stallo` user.
