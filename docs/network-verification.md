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

**Simulated networks inside the lab VM.** Every target listens on TCP
(HTTP) and UDP (an echo server on port 9999), so a blocked connection proves
a filter and not a missing service:

- **netns `inet`, the internet:**
  - `198.51.100.1` and `2001:db8:1::1` serve HTTP on port 80, iperf3,
    and a small DNS server that answers `target.test`;
  - `198.51.100.254` is the default router.
  - These are TEST-NET-2 and documentation addresses, outside every deny
    set.
- **netns `lan`, deny targets that are not the lab's own addresses:**
  `192.168.77.2`, `10.1.2.3`, `172.16.5.5`, `100.100.100.100` (Tailscale
  range), `169.254.9.9` and `fd00:77::2`. Each listens on port 8000.
- **The lab VM itself** (root netns) listens on `[::]:8000`. That covers
  `127.0.0.1`, `::1`, its LAN address `192.168.77.1`, its link-local
  `169.254.9.1`, and two loopback aliases that are in no deny set:
  `203.0.113.7` and `2001:db8:2::7`. These two isolate the
  `fib daddr type local` rule.
  - passt gives the guest the same address as the host's uplink
    (`198.51.100.2`, `2001:db8:1::2`), so those two addresses only reach
    the guest itself. That is why the aliases exist.
- **DNS:** the lab's own resolver is systemd-resolved on `127.0.0.53`.

passt and QEMU ran as the system user `stallo` (uid 999). The guest was
started by hand for these checks. The daemon itself is covered by the M3
gate.

## The six open questions (plan §4)

| # | Question | Result |
|---|---|---|
| 1 | Do passt's outbound sockets carry `skuid stallo`, although passt enters its own user namespace? | **Yes.** `ss -tenp` shows passt's connection to `198.51.100.1:80` as `uid:999`. The table's skuid rule matches it: every deny target below is reachable without the table and blocked with it. |
| 2 | Does `fib daddr type local` work in the output hook? | **Yes**, for IPv4 and IPv6. `203.0.113.7` and `2001:db8:2::7` are in no deny set. Both are reachable without the table and blocked with it. |
| 3 | Does guest DNS through passt resolve when the host resolver is `127.0.0.53`? | **Yes, but guests do not use the host resolver.** On its own, passt finds only a loopback resolver and offers the guest no DNS at all ("Couldn't get any nameserver address"), because loopback mapping is off. `--dns-forward 169.254.1.53` alone relays to `127.0.0.53` and works, but it exposes the host resolver's split DNS (see finding 4). With `--dns-forward 169.254.1.53 --dns-host <public resolver>`, passt hands out `169.254.1.53` over DHCP and relays queries straight to the public resolver (in the lab, `198.51.100.1`). The guest resolved `target.test` and fetched it. |
| 4 | Is `--no-map-gw` still accepted, or is it `--map-host-loopback none` now? | **Both work** in passt 2026-01-20. `--map-host-loopback none` implies `--no-map-gw`. Stallo uses `--map-host-loopback none --map-guest-addr none`. |
| 5 | Does Ubuntu's passt AppArmor profile allow sockets under `/run/stallo/vms/*/`? | **No:** the profile only allows writes under `/tmp`, `$HOME` and libvirt's directories. **It does not matter**, because Stallo passes passt a connected socket (`--fd`), so passt creates no file. passt runs confined (`passt (enforce)`). The only denial logged is its syslog socket (passt still logs to stderr). No override is needed. |
| 6 | Does a RAM snapshot work with `-netdev stream` attached? | **Yes.** `snapshot-save` (0.95 s) and `snapshot-load` (0.71 s) of the 1 GiB guest, with the same separate state image the daemon uses. After the restore, the guest reached the internet target, and new connections to the port forward worked. Connections that were open when the snapshot was taken do not survive a restore: passt has no flows for them. |

## Findings that change the plan

1. **The fail-closed probe must use UDP, not TCP `connect()`.** A TCP SYN
   dropped in the output hook does not fail `connect()` with `EPERM`. The
   kernel ignores the error for a SYN and keeps retransmitting (about
   127 s by default). A UDP `sendto()` to a dropped destination fails at
   once with `EPERM`. Measured as user `stallo` (the TCP rows end at the
   probe's own 3 s socket timeout):

   | Probe | With table | Without table |
   |---|---|---|
   | TCP `connect()` to own `127.0.0.1` listener | timeout | connects |
   | TCP `connect()` to `10.255.255.1:9` | timeout | timeout |
   | UDP `sendto()` to own `127.0.0.1` socket | **`EPERM`** | sent |
   | UDP `sendto()` to own `::1` socket | **`EPERM`** | sent |
   | UDP `sendto()` to `10.255.255.1:9` | **`EPERM`** | sent |
   | UDP `sendto()` to `127.0.0.53:54` | **`EPERM`** | sent |
   | UDP `sendto()` to `127.0.0.53:53` (allowed on purpose) | sent | sent |

   - **What the probe sends:** one datagram each, in this order:
     - to its own `127.0.0.1` and `::1` sockets;
     - to the table's version canary `192.0.2.1:1` (the table's last rule,
       so an older or half-loaded table fails);
     - to one address in each private range (`10/8`, `172.16/12`,
       `192.168/16`, `100.64/10`, `169.254/16`, Tailscale's ULA, NAT64 of
       `10/8`);
     - to `127.0.0.53:54`, to prove the DNS exception is narrow.
     - Loopback goes first, so without the table nothing leaves the host.
   - **Pass condition:** every send must fail with `EPERM`. Any other
     result, including success, refuses the start.
   - **Limit:** `EPERM` does not say which table dropped the packet. The
     canary ties the result to this table's version, but root can still
     edit its other rules unnoticed.
   - **`reject`:** using `reject with icmpx admin-prohibited` instead of
     `drop` changed none of these results. `reject with tcp reset` was not
     tested. The table keeps `drop`.

2. **The table can disappear while VMs run.** The probe at start does not
   cover later changes: `nft flush ruleset` removes the table, and so does
   Ubuntu's `/etc/nftables.conf`, which begins with `flush ruleset`, if the
   nftables service is enabled and reloaded. Running guests would then
   reach everything.
   - The daemon therefore repeats the probe every 0.5 s while an
     `internet` VM has network, and once more right after QEMU and passt
     start.
   - On failure, it kills passt for every `internet` VM. That needs no
     QMP, so a hung or hostile QEMU cannot delay it. The guests keep
     running without network (`ls` shows `running (no network)`) until
     they restart, and a start probes again.
   - **The remaining window:** between the flush and the next probe
     (at most 0.5 s), guests are not isolated.
   - The owner's install reloads the table after such a flush (see
     "Installing on a host").
   - *Changed after review.* The first version paused the guests over
     QMP every 2 s. A QMP `stop` can hang or be ignored, and it does not
     stop QEMU from sending frames to passt.

3. **Port forwards need replies, and only TCP replies may pass.**
   - passt answers a forwarded connection from its own socket (uid
     `stallo`). Its SYN-ACK to `127.0.0.1` matches
     `fib daddr type local` and is dropped, so `127.0.0.1:8080 → guest:80`
     timed out with the plan's table.
   - **`ct state established accept` fixes the forward, but it is a
     bypass.** Conntrack entries belong to the network namespace, not to a
     user, and passt keeps the guest's UDP source port. Measured with that
     rule: a root process on the lab sent UDP from port 40000 to the LAN
     host `192.168.77.2:9999` and got an answer. The guest then sent from
     the same source port to the same LAN host, matched root's entry, and
     **got an answer too**. Ping works the same way through the echo id.
   - **The table uses `meta l4proto tcp ct direction reply accept`
     instead.** Forwards are TCP only.
     - TCP conntrack tracks connection state, so a stallo socket only
       sends reply-direction packets on a connection someone opened to a
       stallo socket: a forward's listener.
     - A SYN in the reply direction of someone else's connection is
       `invalid`, not a reply.
     - The port of another user's listener cannot be bound while it is in
       use.
   - Measured with the new rule: the root process still got its answer, the
     guest's datagram from the same port was blocked, and the forward
     worked.
   - **What is left:** a reply-direction packet from a stallo socket needs
     the far side to have sent to that exact address and port first, as
     in a TCP simultaneous open. A LAN host would have to cooperate. passt
     has no raw sockets to forge one.

4. **The guest does not use the host's resolver.**
   - systemd-resolved on the host applies its split DNS: Tailscale
     MagicDNS names, the router's local zones, reverse lookups of private
     addresses, LLMNR on the LAN, and `/etc/hosts`. A guest that can ask
     it learns the LAN's and tailnet's names. It can also make resolved
     send queries into the LAN.
   - So passt relays guest DNS to a public resolver (`--dns-host`). That
     address is configurable in `stallod.toml` as `net.dns`.
   - The table's `127.0.0.53:53` exception stays only for the daemon's own
     image downloads (`curl` as `stallo`). passt never sends to loopback,
     because no guest address maps to it.
   - passt also relays port 853 (DNS over TLS). Towards `127.0.0.53` the
     table blocks that port; towards the public resolver it is ordinary
     internet traffic.

5. **The table must match the daemon's user positively.**
   - `meta skuid != "stallo" accept` does not match a packet without a
     socket, for example a TCP RST that another table's
     `reject with tcp reset` sends. Such packets then fell through to the
     drop rules.
   - On a production host, that turns other services' refusals towards
     LAN or loopback clients into timeouts. Measured in the lab: a root
     table rejects port 9998 with a TCP reset; from the `lan` netns,
     `curl 192.168.77.1:9998` timed out (exit 28) with the plan's table.
   - With `meta skuid "stallo" jump egress`, packets without a socket and
     other users' packets never reach the drops. The same curl was refused
     at once (exit 7).

6. **passt gets its socket with `--fd`.** QEMU's seccomp filter
   (`src/confine.rs`) denies `connect()`, so QEMU cannot connect to a passt
   socket file. The daemon instead creates a connected `socketpair` and
   gives one end to passt (`--fd`) and the other end to QEMU
   (`-netdev stream,addr.type=fd`).
   - There is no socket file, so no AppArmor path rule is needed and no
     race exists with passt creating it.
   - passt exits when QEMU closes its end (`--fd` implies `--one-off`):
     QEMU `quit` ended passt with status 0.

7. **Blocked connections time out in the guest.** passt sees the drop as a
   connect that never completes, so a guest gets no RST. curl exits with
   code 28 (timeout) instead of 7 (refused). The isolation is not affected.
   Agents should expect timeouts, not refusals, for denied destinations.

8. **Loopback mapping is off in both directions.**
   - Without `--no-map-gw`, passt maps the gateway address to the host's
     loopback: `198.51.100.254:8000` reached the lab's `127.0.0.1:8000`
     when the table was absent, and was blocked when it was loaded.
   - Stallo turns the mapping off anyway (defence in depth). The gateway
     then is the real router: on the lab that is the internet side, and on
     a real LAN it is in `deny4`.
   - Port forwards from `127.0.0.1` still work with mapping off.

## Isolation matrix (S14), nested guest

Run from the guest: TCP with `curl -m 4`, UDP with a 2 s echo request,
ICMP with one `ping`. "Without table" is the control run.

- **The "with table" column** used the final table (below) and the final
  passt flags:
  `--quiet --map-host-loopback none --map-guest-addr none --dns-forward 169.254.1.53 --dns-host 198.51.100.1 -t 127.0.0.1/8080:80 -u none`.
- **The control run** used `--no-map-gw` instead of the two `map` options.
- **The gateway-mapping row** (marked \*) used passt's defaults in both
  columns.

| Target from the guest | Address | Without table | With table |
|---|---|---|---|
| Internet, IPv4 | `198.51.100.1:80` | reached | **reached** |
| Internet, IPv6 | `[2001:db8:1::1]:80` | reached | **reached** |
| Internet by DNS name | `target.test:80` | reached | **reached** |
| Internet, UDP | `198.51.100.1:9999` | reached | **reached** |
| Internet, ping | `198.51.100.1` | reached | **reached** |
| Router (internet side) | `198.51.100.254:80` | reached | **reached** |
| LAN host | `192.168.77.2:8000` | reached | blocked |
| LAN host, UDP | `192.168.77.2:9999` | reached | blocked |
| LAN host, UDP on a host process's conntrack entry | `192.168.77.2:9999` from port 40000 | reached | blocked |
| LAN host, ping | `192.168.77.2` | reached | blocked |
| 10/8 | `10.1.2.3:8000` | reached | blocked |
| 172.16/12 | `172.16.5.5:8000` | reached | blocked |
| Tailscale 100.64/10 | `100.100.100.100:8000` | reached | blocked |
| Link-local | `169.254.9.9:8000` | reached | blocked |
| IPv6 ULA | `[fd00:77::2]:8000` | reached | blocked |
| Host's LAN address | `192.168.77.1:8000` | reached | blocked |
| Host's link-local address | `169.254.9.1:8000` | reached | blocked |
| Host-only IPv4 (only `fib local` matches) | `203.0.113.7:8000` | reached | blocked |
| Host-only IPv6 (only `fib local` matches) | `[2001:db8:2::7]:8000` | reached | blocked |
| The DNS relay address, other port | `169.254.1.53:8000` | refused | blocked |
| Host loopback via the gateway mapping\* | `198.51.100.254:8000` | reached | blocked |
| Port forward, host side | `127.0.0.1:8080 → guest:80` | works | **works** |

- **The conntrack row's control** is the plan's table with
  `ct state established accept` (finding 3), not "no table".
- **Not tested:** multicast and broadcast destinations (passt does not
  relay them, and the table drops them), and IPv4-mapped IPv6 destinations.
  A v4-mapped `sendto` leaves the host as an IPv4 packet, so `deny4` covers
  it; the `::ffff:0:0/96` entry in `deny6` is only a backstop. *Later
  found:* the table's DNS exception does not, see "Known gaps".

## Throughput and latency

Measured in the lab (2 vCPU shared by the nested guest, passt and the
iperf3 server), so the numbers are a floor, not the host's capacity. Each
cell is a single run.

- **Throughput:** iperf3 over 10 s with one TCP stream.
- **RTT:** 2000 one-byte ping-pongs on one TCP connection with
  `TCP_NODELAY`.
- **Target:** `198.51.100.1`.

| Path | Upload (to the target) | Download (from the target) | RTT p50 / mean / p99 |
|---|---|---|---|
| Reference: lab netns → target (veth, no VM) | 40.6 Gbit/s | 41.5 Gbit/s | 14 / 14 / 24 µs |
| Guest via passt, table loaded | 14.1 Gbit/s | 10.2 Gbit/s | 98 / 100 / 139 µs |
| Guest via passt, no table | 14.2 Gbit/s | 10.7 Gbit/s | 95 / 104 / 170 µs |
| Guest via QEMU slirp (`-netdev user`), table loaded | 0.97 Gbit/s | 5.6 Gbit/s | 176 / 400 / 3141 µs |

- **The table costs nothing visible** in these single runs: with and
  without it, the numbers differ by under 5%.
- **passt adds about 85 µs per round trip** over the veth reference. That
  is far below any internet path.
- **slirp is about 15× slower to the target** and has a long latency tail.

## Decision: passt

- **passt it is.** Its sockets carry the daemon's uid, so the table applies
  to them (check 1). It is 2 to 15 times faster than slirp, and it runs in
  its own sandbox: its own namespaces, seccomp and AppArmor profile.
- **The slirp fallback is not needed.** It would also cost confinement:
  slirp runs inside QEMU, so QEMU would need `socket(AF_INET)` and
  `connect()`.
  - seccomp cannot inspect `connect()`'s address, and QEMU must keep its
    `AF_UNIX` sockets.
  - Landlock restricts `connect()` to pathname Unix sockets only from ABI 9
    (Linux 7.1); this host runs 7.0.
  - So allowing `connect()` would let QEMU reach the daemon's API socket
    and other VMs' QMP sockets, which the filter blocks today. Landlock
    would also have to allow TCP connects to every port.

**The table** (the plan's draft plus findings 3 and 5 and the deny-set
review):

```
table inet stallo {
  set deny4 { type ipv4_addr; flags interval; elements = {
    0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16,
    172.16.0.0/12, 192.0.0.0/24, 192.168.0.0/16, 198.18.0.0/15,
    224.0.0.0/4, 240.0.0.0/4 } }
  set deny6 { type ipv6_addr; flags interval; elements = {
    ::/128, ::1/128, ::ffff:0:0/96,
    64:ff9b::7f00:0/104, 64:ff9b::a00:0/104, 64:ff9b::a9fe:0/112,
    64:ff9b::ac10:0/108, 64:ff9b::c0a8:0/112, 64:ff9b::6440:0/106,
    64:ff9b:1::/48, 100::/64, fc00::/7, fec0::/10, fe80::/10, ff00::/8 } }
  chain output {
    type filter hook output priority filter; policy accept;
    meta skuid "stallo" jump egress
  }
  chain egress {
    meta l4proto tcp ct direction reply accept
    ip daddr 127.0.0.53 meta l4proto { tcp, udp } th dport 53 accept
    fib daddr type { local, broadcast, multicast, anycast } drop
    ip daddr @deny4 drop
    ip6 daddr @deny6 drop
    ip daddr 192.0.2.1 udp dport 1 drop
  }
}
```

- **The last rule is the version canary** for the probe (added after
  review). `packaging/stallo.nft` is this table with comments.

- **NAT64:** the `64:ff9b::` entries are the well-known NAT64 prefix with
  a private IPv4 range embedded, because a NAT64 gateway on the LAN would
  translate them back into the LAN. NAT64 to public addresses keeps
  working.
- **The uid is fixed at load time.** `meta skuid "stallo"` is resolved to
  the numeric uid when the table is loaded (`nft list` shows `999`). If
  the user is recreated with another uid, the table must be reloaded.
  Otherwise the probe fails and `internet` starts are refused, which is
  fail closed.

## Known gaps

### IPv4-mapped loopback DNS (found 2026-10-17; guests are IPv4 only since)

- **The gap.** passt drops guest frames whose source or destination is
  `127.0.0.0/8` or `::1` (passt `tap.c`, IPv4 and IPv6 handlers), but not
  an IPv6 frame to the IPv4-mapped `::ffff:127.0.0.53`. passt treats that
  address as IPv4 (`nat_outbound` in `fwd.c` passes it on unchanged) and
  opens an IPv4 socket to `127.0.0.53:53` as user `stallo`. The table's
  exception for the daemon's own downloads,
  `ip daddr 127.0.0.53 … th dport 53 accept`, comes before the
  `fib daddr type local` drop, so the query reaches the host's resolver
  and its answer goes back to the guest. A guest that crafts such frames
  (admin rights in the guest) could ask the host's split DNS: tailnet and
  LAN names, `/etc/hosts`, and make resolved send LLMNR or mDNS queries
  into the LAN. It needs IPv6 in passt, that is, IPv6 on the host.
- **Evidence.** passt `0.0~git20260120.386b5f5-1` (Ubuntu's) in an offline
  nested guest, our exact flags, `--fd` from a socketpair, a dummy uplink
  with IPv4 and IPv6 default routes, and a logging UDP/TCP responder on
  `127.0.0.53:53`. Frames sent by a test client:

  | Frame | Without `-4` | With `-4` |
  |---|---|---|
  | IPv4 UDP to `127.0.0.53:53` | dropped (`Loopback address on tap interface`) | dropped |
  | IPv6 UDP to `[::ffff:127.0.0.53]:53` | **relayed**: the responder logged a query from `127.0.0.1:40001`, and the guest got the DNS answer from `::ffff:127.0.0.53:53` | dropped, nothing reached the responder |
  | IPv6 TCP SYN to `[::ffff:127.0.0.53]:53` | passt was killed by its seccomp filter (signal 31): the guest loses only its own network | dropped |

- **Mitigation now.** passt runs with `-4` (`net::passt_args`): guests get
  IPv4 only, no IPv6 internet. passt then refuses IPv6 listeners, so
  IPv6 port forwards (`--bind ::1`) are refused at create and start.
  passt has no option that drops IPv4-mapped destinations.
- **Plan to get IPv6 back** (not done): allow the resolver only to the
  daemon's helper programs, which run in the `tools/` leaf of the
  daemon's cgroup (`src/cgroup.rs`), never in a `vm-<name>/` leaf where
  passt runs:

  ```
  socket cgroupv2 level 3 "system.slice/stallod.service/tools" ip daddr 127.0.0.53 meta l4proto { tcp, udp } th dport 53 accept
  ```

  - nft resolves the path to a cgroup id when the rule is loaded. The
    path must exist then, and the id changes whenever stallod restarts
    (systemd recreates its cgroup). So the rule must load after stallod
    created `tools/`, in a small table of its own, replaced on every
    start. `stallod.service` is `Type=exec`, so a plain `ExecStartPost`
    runs before `tools/` exists: switch to `Type=notify` with `READY=1`
    after the cgroup setup, or use a root helper that waits for the path.
    Until the rule is loaded, downloads fail (fail closed).
  - The isolation probe should then also expect `EPERM` for UDP to
    `127.0.0.53:53` sent from the `daemon/` leaf.
  - Then drop `-4` and re-run the frames above: the IPv6 UDP row must be
    dropped by the table.

## Not covered here

- **The table works per user, not per VM.** It applies to every process of
  user `stallo`: the daemon, every QEMU and every passt, whatever the VM's
  profile. If uid 999 is ever given to another account, that account is
  silently confined. Per-VM rules would need another match, such as
  `socket cgroupv2` on the VM cgroups.
- **IPv6 on a real LAN.** If the host's LAN has global IPv6, other LAN
  hosts have internet addresses that no deny set can tell apart from the
  internet. Their ULA and link-local addresses are blocked, their global
  addresses are not. The owner can add the LAN's IPv6 prefix to `deny6`.
- **Hosts behind other interfaces.**
  - Other networks reached through the host's routes count as internet
    unless their ranges are in a deny set. Examples are a VPN that is not
    Tailscale, or routed public prefixes.
  - Docker's default bridges and libvirt's are inside `172.16.0.0/12` and
    `192.168.0.0/16`.
  - A stricter host can add `meta oifname != "<uplink>" drop` to the
    `egress` chain, which also catches custom address pools.

## M3 gate: the daemon in the lab

`tests/lab/m3-network.sh` runs the gate inside the lab VM. It refuses to
run unless `/etc/stallo-lab` exists and `systemd-detect-virt --vm`
succeeds, so it cannot run on a real host by accident. It does the
following:

- builds the simulated networks above;
- loads `packaging/stallo.nft`;
- starts `stallod` in production mode as user `stallo` (`systemd-run
  --uid=stallo -p Delegate=yes`);
- drives everything through the `stallo` CLI.

The final run used release binaries built from the M3-4 branch after the
review fixes, a fresh boot of the lab VM, and `[net] dns = "198.51.100.1"`
(the lab's internet resolver).

| Check | Result |
|---|---|
| Controls: every deny target answers user `nobody`, whom the table does not match (13 checks) | answered |
| S15: `stallo new --net internet` with no table loaded | refused: `isolation unavailable` |
| Create an `internet` VM with `--forward 8080:80` | ready in 20–25 s on first boot (cloud-init, DHCP and wait-online included) |
| S14: internet over IPv4, IPv6, DNS name, UDP and ping | reached |
| S14: LAN host (TCP, UDP, ping), 10/8, 172.16/12, 100.64/10, link-local, IPv6 ULA (TCP, UDP), host LAN and link-local addresses, host-only IPv4 and IPv6 | blocked |
| Port forward `127.0.0.1:8080 → 80` | works; nothing listens on `198.51.100.2:8080` |
| RAM snapshot and restore with passt attached | works; internet and forward work after the restore |
| S15: table deleted while the VM runs | `running (no network)` within 2 s; the guest cannot reach the internet target either |
| S15: another `internet` VM while the table is gone | refused: `isolation unavailable` |
| Stop and start after reloading the table | internet works again |
| IPv6 port forward `[::1]:8081 → 80` | works |

All 47 checks passed. Dev mode refuses `internet` at create and start
(unit test, `run::tests::internet_is_refused`).

**An IPv6 forward reaches the guest over IPv6.** passt keeps the address
family, so a guest service must listen on IPv6 too: Python's
`http.server` bound only `0.0.0.0` until it was given `--bind ::`.

**Measured through the product** (1 vCPU, 1 GiB guest; 3 runs each).
This was measured with the build before the review fixes. Those fixes
changed passt's arguments by `--search none` and a 4096 open-file limit.
Neither is on the data path, but the numbers were not measured again.

| | Run 1 | Run 2 | Run 3 |
|---|---|---|---|
| Upload to the target (iperf3, 10 s) | 6.39 Gbit/s | 6.35 Gbit/s | 6.18 Gbit/s |
| Download from the target | 5.11 Gbit/s | 4.50 Gbit/s | 4.80 Gbit/s |
| RTT p50 / mean / p99 | 128 / 232 / 261 µs | 138 / 232 / 260 µs | 136 / 231 / 253 µs |

- **Slower than the hand-started passt above** (14.1 / 10.2 Gbit/s,
  98 µs) because passt runs in the VM's cgroup. It shares the VM's CPU
  quota (`cpu.max` = vCPUs × 100%) with the guest.
  - During a 10 s upload the cgroup used 0.94 CPU and was throttled in 91
    of 100 periods.
  - That is on purpose: the network work of a VM counts against that VM,
    not the host. A guest with more vCPUs gets more.
- **The mean RTT is close to the p99:** under 1% of the round trips took
  several milliseconds, when the quota ran out.
- **Memory:** passt's RSS was 18–21 MiB. `internet` VMs get 64 MiB more
  cgroup memory for it (after review). Before that, the cgroup peaked at
  922–1074 MiB of 1280 MiB, with no OOM.
- **Confinement:** passt ran as uid 999 under its AppArmor profile
  (`passt (enforce)`).
- **Restart time:** a restart (no first-boot work) without an IPv6
  default route was ready in 12 s.

## Installing on a host

This is an owner task: it needs root, and it changes the host's firewall.
Do it only after the lab gate.

**What it changes:**
- **Matched:** packets from sockets of user `stallo` only. Other users,
  other services and packets without a socket are not matched. In the lab,
  root's traffic and another table's TCP resets were unaffected.
- **Until a `stallo` daemon runs `internet` VMs,** nothing sends as that
  user.
- **Host-wide side effect:** the table's `ct` match turns on connection
  tracking for IPv4 and IPv6 for the whole host (shared
  `nf_conntrack_max`, 262144 here). IPv4 is likely tracked already
  (Docker); IPv6 may be new.

**Check the host first.** Both checks are read-only:

- `ip -6 addr show scope global`
  - If it shows addresses, the LAN has global IPv6. Guests could then
    reach LAN devices by their global addresses, because no deny set can
    tell them from the internet.
  - Add the LAN prefix to `deny6`, or do not enable `internet` VMs. A
    prefix that changes over time makes the entry stale, which fails open.
  - On 2026-10-13 this host had no global IPv6 address.
- **The router's public (WAN) address** is not in any deny set.
  - Many home routers answer on it from inside: their admin page, or
    hairpin NAT to the LAN's port forwards.
  - If yours does, add the WAN address to `deny4`.

**Since M5 the package does steps 1, 2, 3 and 5** (passt as a dependency,
the user, the table and `stallo-nft.service`); follow
[production.md](production.md) instead. The manual steps below remain for
reference.

**Steps.** Roll back in reverse order, 5 to 1.

1. **Install passt:**
   - `sudo apt install passt`
   - Rollback: `sudo apt remove passt`
2. **Create the user.** The table resolves the user's uid when it loads.
   - `sudo useradd --system --no-create-home --shell /usr/sbin/nologin --groups kvm stallo`
   - Rollback: `sudo userdel stallo`. Undo steps 3 to 5 first: a table
     file that names a missing user does not load.
3. **Load the table:**
   - `sudo install -D -m 644 packaging/stallo.nft /etc/stallo/stallo.nft`
   - `sudo nft -f /etc/stallo/stallo.nft`
   - Check that it exists: `sudo nft list table inet stallo`
   - Rollback: `sudo nft delete table inet stallo && sudo rm /etc/stallo/stallo.nft`
4. **Check that it works.** `<router>` is your LAN router's address.
   - `sudo -u stallo curl -m 3 http://<router>/` must fail with
     "Operation not permitted" or time out.
   - `sudo -u stallo curl -m 3 http://127.0.0.1:<some local service port>/` must
     also fail.
   - `sudo -u stallo curl -sI -m 5 https://example.com` must work (DNS
     through `127.0.0.53` is allowed for the daemon).
   - Your own user's `curl http://<router>/` must still work.
5. **Optional: keep the table across reboots.** Without this, the table is
   gone after a reboot and `internet` VMs are refused (fail closed) until
   it is loaded again. The unit is
   `/etc/systemd/system/stallo-nft.service`:

   ```
   [Unit]
   Description=Stallo network isolation table
   After=nftables.service

   [Service]
   Type=oneshot
   RemainAfterExit=yes
   ExecStart=/usr/sbin/nft -f /etc/stallo/stallo.nft
   ExecReload=/usr/sbin/nft -f /etc/stallo/stallo.nft

   [Install]
   WantedBy=multi-user.target
   ```

   - **Why it looks like this:**
     - There is no `ExecStop`: removing the table is the manual rollback
       in step 3, not a side effect of `systemctl stop` or `restart`.
     - A reload replaces the table in one transaction.
     - It is not ordered before the network, because stallod fails closed
       without the table.
   - Check it first: `sudo systemd-analyze verify /etc/systemd/system/stallo-nft.service`
   - Enable it: `sudo systemctl daemon-reload && sudo systemctl enable --now stallo-nft`
   - Rollback: `sudo systemctl disable stallo-nft && sudo rm /etc/systemd/system/stallo-nft.service && sudo systemctl daemon-reload`
   - **If `nftables.service` is enabled:** a reload of
     `/etc/nftables.conf` runs `flush ruleset` and removes this table.
     Running `internet` guests then lose their network within 0.5 s.
     Afterwards, run `sudo systemctl reload stallo-nft`.
     - Do not `include` the table in `/etc/nftables.conf`: if user
       `stallo` is ever removed, the whole host firewall would then fail
       to load.

**After the install:**
- **The daemon:** `internet` VMs still need `stallod` in production mode
  as user `stallo`. That service is packaged in M5, and it should be
  ordered `After=stallo-nft.service`. Dev mode keeps refusing `internet`.
- **Guest DNS:** `[net] dns` in `/var/lib/stallo/stallod.toml` picks the
  public IPv4 resolver for guests (default `9.9.9.9`, Quad9).
- **The table also limits the daemon itself.** Its image downloads cannot
  use a proxy or mirror on the LAN or on localhost.

## Windows guests

**Not verified yet.** The lab above used Linux guests. Windows guests and
VMs from any imported ISO take the `internet` profile with the same passt
flags and the same table. So do VMs from a catalog ISO. This checklist is
for the owner's first Windows VM on a production install.

**Why nothing changes for the isolation:**
- Everything is enforced on the host. passt turns the guest's frames into
  sockets of user `stallo`, the table drops those to denied addresses, and
  passt runs under its AppArmor profile. Nothing is configured inside the
  guest.
- A guest that sets its own address, gateway or DNS server still only
  reaches passt. Its packets to a LAN DNS server or router leave the host
  as `stallo` sockets and are dropped.
- The catalog's per-image `internet` flag does not apply. It exists
  because a cloud image's seed (`network-config`) must match the NIC, or
  DHCP never comes up and the VM is never ready. A VM from an ISO
  (imported or from the catalog) has no seed: the installed OS asks
  passt's DHCP itself.

**What the guest gets** (passt's behaviour, not checked with Windows):
- An Intel 82574L card (QEMU `e1000e`), which Windows has a driver for.
- IPv4 by DHCP: **the laptop's own LAN address** and its default gateway
  (passt copies them), DNS server `169.254.1.53`, no search domain.
- No IPv6: passt runs IPv4 only (see "Known gaps").
- Windows ignores DHCP's MTU option and keeps 1500. passt sizes TCP
  segments to the guest's MSS, so this should not matter.

**Before you start, on the laptop:**
1. Do "Check the host first" under "Installing on a host". If the LAN
   has global IPv6, or the router answers on its WAN address, **do not
   continue** until the LAN's IPv6 prefix is in `deny6` and the WAN
   address in `deny4` (`/etc/stallo/stallo.nft`, then
   `sudo systemctl reload stallo-nft`).
2. Check the table: `sudo nft list table inet stallo` must print it.
3. Note the addresses to test, with `ip -br addr` and `ip route show default`:
   - `<gw>`: the default gateway (your router);
   - `<lan-dev>`: another device on the LAN with a known open port, for
     example a NAS or printer web page;
   - `<host-other>`: any other address of the laptop that is not its LAN
     address (`docker0`, `virbr0`, `tailscale0`), if it has one;
   - `<lan-v6>`: a LAN device's global IPv6 address, if the LAN has global
     IPv6 (`ip -6 neigh` on the laptop lists neighbours);
   - `<wan>`: the router's public address (its status page, or
     `curl -s https://ifconfig.me` from the laptop).
4. Controls, as your own user on the laptop: `curl -m 3 http://<gw>/`
   and the `<lan-dev>` page answer.
5. Optional, to prove that no guest address reaches the laptop's
   loopback: `python3 -m http.server 8000 --bind 127.0.0.1` in a
   terminal (loopback only; stop it with Ctrl+C afterwards).
6. Create the VM: `stallo new win --image local-<id> --net internet`.
   The profile is fixed at `new`; an offline VM must be made again.

**Inside Windows**, in PowerShell (during Setup: Shift+F10, then
`powershell`):

| # | Command | Expected |
|---|---|---|
| 1 | `ipconfig /all` | The Intel 82574L adapter, `DHCP Enabled: Yes`, the laptop's LAN address, `Default Gateway` = `<gw>`, `DNS Servers` = `169.254.1.53`, no DNS suffix |
| 2 | `nslookup example.com` | `Address: 169.254.1.53` as server, and an answer |
| 3 | `Test-NetConnection example.com -Port 443` | `TcpTestSucceeded : True` |
| 4 | `curl.exe -sI https://www.google.com` | `HTTP/1.1 200` (or a redirect) |
| 5 | In Edge, download and install Chrome; browse a few sites | works |
| 6 | `curl.exe -6 -sI https://ipv6.google.com` | fails: no IPv6 (passt `-4`) |
| 7 | `Test-NetConnection <gw> -Port 80` | `TcpTestSucceeded : False` (after a timeout) |
| 8 | `Test-NetConnection <lan-dev> -Port <its port>` | `False` |
| 9 | `nslookup example.com <gw>` (UDP to the router's DNS) | `timed out` |
| 10 | `Test-NetConnection <host-other> -Port 22` (each one) | `False` |
| 11 | With step 5's server: `Test-NetConnection <gw> -Port 8000` and `Test-NetConnection 169.254.1.53 -Port 8000` | `False`: neither address is mapped to the laptop's loopback (this row tests only that mapping) |
| 12 | `Test-NetConnection 169.254.169.254 -Port 80`, `Test-NetConnection 10.0.0.1 -Port 80` | `False` |
| 13 | If the laptop runs Tailscale: `Test-NetConnection 100.100.100.100 -Port 53`, and `nslookup <laptop's tailnet name>` | `False`; no tailnet answer |
| 14 | `ping <gw>` | no replies |
| 15 | If the LAN has global IPv6: `Test-NetConnection <lan-v6> -Port <its port>` | `False` |
| 16 | `Test-NetConnection <wan> -Port 80` and `-Port 443` | `False` |

- **Blocked means a timeout**, not "refused" (finding 7). A `True` in rows
  7 to 13, 15 or 16 is an isolation failure: stop the VM (`stallo stop win`) and
  report it.
- Testing the laptop's LAN address from Windows proves nothing: it is the
  guest's own address, so Windows answers itself.
- `ping` to internet hosts may fail even when the internet works: passt
  needs ping sockets for it (`net.ipv4.ping_group_range`). Use rows 3 and 4.
- If pages stall while small requests work, note the output of
  `netsh interface ipv4 show subinterfaces` (MTU) with the report.

**Optional, fail closed** (changes the laptop's firewall for a moment):
`sudo nft delete table inet stallo`. Within 2 s `stallo ls` shows
`running (no network)` and row 3 fails. Roll back with
`sudo systemctl reload stallo-nft`, then `stallo stop win && stallo start win`.
