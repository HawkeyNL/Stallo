# Network verification (M3): the `internet` profile

The `internet` profile lets a guest reach the internet and nothing else:
not the host's loopback services, not the host's own addresses, not the LAN,
Tailscale, link-local or multicast. passt gives the guest its network, and
an nftables table on the host enforces the isolation. This document records
what was checked in the lab VM before the code was written, and why the
design is the way it is.

## Lab

Nothing here ran on the production host's network. The host only ran one
offline lab VM, and all networking happened inside it.

| Item | Value |
|---|---|
| Lab VM | Ubuntu 26.04 cloud image, 2 vCPU, 3 GiB, `-nic none`, nested KVM |
| Nested guest | Ubuntu 26.04 cloud image, 1 vCPU, 1 GiB, OVMF |
| Kernel | 7.0.0-34-generic (lab and nested guest) |
| passt | `0.0~git20260120.386b5f5-1` (runs as `passt.avx2`) |
| QEMU | 10.2.1 (`1:10.2.1+ds-1ubuntu3.2`) |
| nftables | 1.1.6 |

The packages went into the offline lab VM as `.deb` files on a read-only
ISO. They were fetched on the host with `apt-get download` (no root), and
each file's SHA-256 was checked against apt's signed index before use.

**Simulated networks inside the lab VM.** Every target listens on TCP, so a
blocked connection proves a filter and not a missing service:

- **netns `inet`, the internet:**
  - `198.51.100.1` and `2001:db8:1::1` serve HTTP on port 80 and iperf3;
  - `198.51.100.254` is the default router.
  - These are TEST-NET-2 and documentation addresses, outside every deny
    set.
- **netns `lan`, deny targets that are not the lab's own addresses:**
  `192.168.77.2`, `10.1.2.3`, `172.16.5.5`, `100.100.100.100` (Tailscale
  range), `169.254.9.9` and `fd00:77::2`. Each listens on port 8000.
- **The lab VM itself** (root netns) listens on `[::]:8000`. That covers
  `127.0.0.1`, `::1`, its LAN address `192.168.77.1`, its link-local
  `169.254.9.1`, and two addresses that are in no deny set:
  `203.0.113.7` and `2001:db8:2::7`. These two isolate the
  `fib daddr type local` rule.
- **DNS:** the lab's resolver is systemd-resolved on `127.0.0.53`. It
  answers `target.test` from `/etc/hosts`.

passt and QEMU ran as the system user `stallo` (uid 999). The guest was
started by hand for these checks. The daemon itself is covered by the M3
gate.

## The six open questions (plan §4)

| # | Question | Result |
|---|---|---|
| 1 | Do passt's outbound sockets carry `skuid stallo`, although passt enters its own user namespace? | **Yes.** `ss -tenp` shows passt's connection to `198.51.100.1:80` as `uid:999`. The table's skuid rule matches it: every deny target below is reachable without the table and blocked with it. |
| 2 | Does `fib daddr type local` work in the output hook? | **Yes**, for IPv4 and IPv6. `203.0.113.7` and `2001:db8:2::7` are in no deny set. Both are reachable without the table and blocked with it. |
| 3 | Does guest DNS through passt resolve when the host resolver is `127.0.0.53`? | **Yes, with `--dns-forward`.** On its own, passt finds only a loopback resolver and offers the guest no DNS at all ("Couldn't get any nameserver address"), because loopback mapping is off. With `--dns-forward 169.254.1.53`, passt hands out `169.254.1.53` over DHCP and relays queries to `127.0.0.53`. The table allows that one destination (`127.0.0.53`, port 53). The guest resolved `target.test` and fetched it. |
| 4 | Is `--no-map-gw` still accepted, or is it `--map-host-loopback none` now? | **Both work** in passt 2026-01-20. `--map-host-loopback none` implies `--no-map-gw`. Stallo uses `--map-host-loopback none --map-guest-addr none`. |
| 5 | Does Ubuntu's passt AppArmor profile allow sockets under `/run/stallo/vms/*/`? | **No:** the profile only allows writes under `/tmp`, `$HOME` and libvirt's directories. **It does not matter**, because Stallo passes passt a connected socket (`--fd`), so passt creates no file. passt runs confined (`passt (enforce)`). The only denial logged is its syslog socket (passt still logs to stderr). No override is needed. |
| 6 | Does a RAM snapshot work with `-netdev stream` attached? | **Yes.** `snapshot-save` (0.95 s) and `snapshot-load` (0.71 s) of the 1 GiB guest, with the same separate state image the daemon uses. After the restore, the guest reached the internet target again, and the port forward kept working. |

## Findings that change the plan

1. **The fail-closed probe must use UDP, not TCP `connect()`.** A TCP SYN
   dropped in the output hook does not fail `connect()` with `EPERM`: the
   kernel just retransmits, and `connect()` times out. A UDP `sendto()`
   to a dropped destination fails at once with `EPERM`. Measured as user
   `stallo`:

   | Probe | With table | Without table |
   |---|---|---|
   | TCP `connect()` to own `127.0.0.1` listener | timeout (3 s) | connects |
   | TCP `connect()` to `10.255.255.1:9` | timeout (3 s) | timeout (3 s) |
   | UDP `sendto()` to own `127.0.0.1` socket | **`EPERM`** | sent |
   | UDP `sendto()` to `10.255.255.1:9` | **`EPERM`** | sent |

   The probe therefore sends one UDP datagram to its own `127.0.0.1`
   socket and one to `10.255.255.1:9`. Both must fail with `EPERM`. Any
   other result, including success, refuses the start. Using `reject`
   instead of `drop` changed none of these results, so the table keeps
   `drop`.

2. **Port forwards need `ct state established accept`.** passt answers a
   forwarded connection from its own socket (uid `stallo`). Its SYN-ACK to
   `127.0.0.1` matches `fib daddr type local` and is dropped, so
   `127.0.0.1:8080 → guest:80` timed out with the plan's table. With
   `ct state established accept` placed before the drop rules, the forward
   works.
   - This does not open egress. The first packet of every connection passt
     starts is `new` and still hits the drop rules. So does every UDP
     datagram to a new destination.
   - Only a flow that the other side started (a forwarded connection, or a
     datagram a host process sends to passt first) can carry replies.

3. **passt gets its socket with `--fd`.** QEMU's seccomp filter
   (`src/confine.rs`) denies `connect()`, so QEMU cannot connect to a passt
   socket file. The daemon instead creates a connected `socketpair` and
   gives one end to passt (`--fd`) and the other end to QEMU
   (`-netdev stream,addr.type=fd`).
   - There is no socket file, so no AppArmor path rule is needed and no
     race exists with passt creating it.
   - passt exits when QEMU closes its end (`--fd` implies `--one-off`):
     QEMU `quit` ended passt with status 0.

4. **Blocked connections time out in the guest.** passt sees the drop as a
   connect that never completes, so a guest gets no RST. curl exits with
   code 28 (timeout) instead of 7 (refused). The isolation is not affected.
   Agents should expect timeouts, not refusals, for denied destinations.

5. **Loopback mapping is off in both directions.**
   - Without `--no-map-gw`, passt maps the gateway address to the host's
     loopback: `198.51.100.254:8000` reached the lab's `127.0.0.1:8000`
     when the table was absent, and was blocked when it was loaded.
   - Stallo turns the mapping off anyway (defence in depth). The gateway
     then is the real router: on the lab that is the internet side, and on
     a real LAN it is in `deny4`.
   - Port forwards from `127.0.0.1` still work with mapping off.

## Isolation matrix (S14), nested guest

Run from the guest with `curl -m 4`. "Without table" is the control run.
The "with table" column used the final passt flags:
`--quiet --map-host-loopback none --map-guest-addr none --dns-forward 169.254.1.53 -t 127.0.0.1/8080:80 -u none`.
The control run used `--no-map-gw` instead of the two `map` options, and
the gateway-mapping row used passt's defaults in both columns (marked \*).

| Target from the guest | Address | Without table | With table |
|---|---|---|---|
| Internet, IPv4 | `198.51.100.1:80` | reached | **reached** |
| Internet, IPv6 | `[2001:db8:1::1]:80` | reached | **reached** |
| Internet by DNS name | `target.test:80` | reached | **reached** |
| LAN host | `192.168.77.2:8000` | reached | blocked |
| 10/8 | `10.1.2.3:8000` | reached | blocked |
| 172.16/12 | `172.16.5.5:8000` | reached | blocked |
| Tailscale 100.64/10 | `100.100.100.100:8000` | reached | blocked |
| Link-local | `169.254.9.9:8000` | reached | blocked |
| IPv6 ULA | `[fd00:77::2]:8000` | reached | blocked |
| Host's LAN address | `192.168.77.1:8000` | reached | blocked |
| Host's link-local address | `169.254.9.1:8000` | reached | blocked |
| Host-only IPv4 (only `fib local` matches) | `203.0.113.7:8000` | reached | blocked |
| Host-only IPv6 (only `fib local` matches) | `[2001:db8:2::7]:8000` | reached | blocked |
| Host loopback via the gateway mapping\* | `198.51.100.254:8000` | reached | blocked |
| Port forward, host side | `127.0.0.1:8080 → guest:80` | works | **works** |

The guest has the same address as the host's uplink (`198.51.100.2`,
passt's default), so connecting to that address only reaches the guest
itself.

## Throughput and latency

Measured in the lab (2 vCPU shared by the nested guest, passt and the
iperf3 server), so the numbers are a floor, not the host's capacity.
Throughput is iperf3 over 10 s with one TCP stream. RTT is 2000 one-byte
ping-pongs on one TCP connection with `TCP_NODELAY`. The target is
`198.51.100.1`.

| Path | Guest → target | Target → guest | RTT p50 / mean / p99 |
|---|---|---|---|
| Lab netns → target (veth, no VM; reference) | 40.6 Gbit/s | 41.5 Gbit/s | 14 / 14 / 24 µs |
| Guest via passt, table loaded | 14.1 Gbit/s | 10.2 Gbit/s | 98 / 100 / 139 µs |
| Guest via passt, no table | 14.2 Gbit/s | 10.7 Gbit/s | 95 / 104 / 170 µs |
| Guest via QEMU slirp (`-netdev user`), table loaded | 0.97 Gbit/s | 5.6 Gbit/s | 176 / 400 / 3141 µs |

- **The table costs nothing measurable**: the differences are within run
  to run noise.
- **passt adds about 85 µs per round trip** over the veth reference. That
  is far below any internet path.
- **slirp is about 15× slower guest → target** and has a long latency
  tail.

## Decision: passt

- **passt it is.** Its sockets carry the daemon's uid, so the table applies
  to them (check 1). It is 2 to 15 times faster than slirp, and it runs in
  its own sandbox: its own namespaces, seccomp and AppArmor profile.
- **The slirp fallback is not needed.** It would also cost confinement:
  slirp runs inside QEMU, so QEMU's seccomp filter would have to allow
  `AF_INET` sockets and `connect()`. seccomp cannot tell a TCP `connect()`
  from a Unix-socket `connect()`, so QEMU could then reach the daemon's API
  socket and other VMs' QMP sockets, which the filter blocks today.

**Table used in the lab** (the plan's draft plus finding 2):

```
table inet stallo {
  set deny4 { type ipv4_addr; flags interval; elements = {
    0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16,
    172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } }
  set deny6 { type ipv6_addr; flags interval; elements = {
    ::1/128, ::ffff:0:0/96, fc00::/7, fe80::/10, ff00::/8 } }
  chain output {
    type filter hook output priority filter; policy accept;
    meta skuid != "stallo" accept
    ct state established accept
    ip daddr 127.0.0.53 meta l4proto { tcp, udp } th dport 53 accept
    fib daddr type local drop
    ip daddr @deny4 drop
    ip6 daddr @deny6 drop
  }
}
```

`meta skuid "stallo"` is resolved to the numeric uid when the table is
loaded (`nft list` shows `999`). If the user is ever recreated with another
uid, the table must be reloaded. Otherwise the probe fails and `internet`
starts are refused, which is fail closed.

## Not covered here

- **IPv6 on a real LAN.** If the host's LAN has global IPv6, other LAN
  hosts have internet addresses that no deny set can tell apart from the
  internet. Their ULA and link-local addresses are blocked, their global
  addresses are not. The owner can add the LAN's IPv6 prefix to `deny6`.
- **Hosts reachable only through the host's routes** (a VPN that is not
  Tailscale, or routes to public prefixes) count as internet unless their
  ranges are added to the deny sets.
- **The daemon-driven gate** (production-mode daemon as `stallo`, the
  probe, `stallo new --net internet`, port forwards, S15) is checked in M3-4
  and recorded below when it has run.
