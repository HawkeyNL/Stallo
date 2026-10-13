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

   - **What the probe sends:** one datagram each to its own `127.0.0.1`
     and `::1` sockets, to `10.255.255.1:9`, and to `127.0.0.53:54`. That
     covers both address families, a private range, and the narrowness of
     the DNS exception.
   - **Pass condition:** every send must fail with `EPERM`. Any other
     result, including success, refuses the start.
   - **Limit:** `EPERM` does not say which table dropped the packet. The
     probe proves that egress of the daemon's user is filtered, not that
     the filter is exactly `inet stallo`.
   - **`reject`:** using `reject with icmpx admin-prohibited` instead of
     `drop` changed none of these results. `reject with tcp reset` was not
     tested. The table keeps `drop`.

2. **The table can disappear while VMs run.** The probe at start does not
   cover later changes: `nft flush ruleset` removes the table, and so does
   Ubuntu's `/etc/nftables.conf`, which begins with `flush ruleset`, if the
   nftables service is enabled and reloaded. Running guests would then
   reach everything.
   - The daemon therefore repeats the probe every 2 s while an `internet`
     VM runs.
   - On failure, it pauses every `internet` VM. `stallo resume` works only
     once the probe passes again.
   - The owner's install keeps the table out of `/etc/nftables.conf`'s
     flush, or includes it there.

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
  it; the `::ffff:0:0/96` entry in `deny6` is only a backstop.

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
  }
}
```

- **NAT64:** the `64:ff9b::` entries are the well-known NAT64 prefix with
  a private IPv4 range embedded, because a NAT64 gateway on the LAN would
  translate them back into the LAN. NAT64 to public addresses keeps
  working.
- **The uid is fixed at load time.** `meta skuid "stallo"` is resolved to
  the numeric uid when the table is loaded (`nft list` shows `999`). If
  the user is recreated with another uid, the table must be reloaded.
  Otherwise the probe fails and `internet` starts are refused, which is
  fail closed.

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
run unless `/etc/stallo-lab` exists, so it cannot run on a real host by
accident. It does the following:

- builds the simulated networks above;
- loads `packaging/stallo.nft`;
- starts `stallod` in production mode as user `stallo` (`systemd-run
  --uid=stallo -p Delegate=yes`);
- drives everything through the `stallo` CLI.

The run used release binaries built from the M3-4 branch, a fresh boot of
the lab VM, and `[net] dns = "198.51.100.1"` (the lab's internet resolver).

| Check | Result |
|---|---|
| S15: `stallo new --net internet` with no table loaded | refused: `isolation unavailable` |
| Create an `internet` VM with `--forward 8080:80` | ready in 22–25 s (DHCP and wait-online included) |
| S14: internet over IPv4, IPv6, DNS name, UDP and ping | reached |
| S14: LAN host (TCP, UDP, ping), 10/8, 172.16/12, 100.64/10, link-local, IPv6 ULA (TCP, UDP), host LAN and link-local addresses, host-only IPv4 and IPv6, gateway on another port | blocked |
| Port forward `127.0.0.1:8080 → 80` | works; nothing listens on `198.51.100.2:8080` |
| RAM snapshot and restore with passt attached | works; internet and forward work after the restore |
| S15: table deleted while the VM runs | VM shows `paused (isolation lost)` within 5 s |
| `stallo resume` without the table | refused: `isolation unavailable` |
| `stallo resume` after reloading the table | resumes; internet works |

All 30 checks passed. Dev mode refuses `internet` at create and start
(unit test, `run::tests::internet_is_refused`).

**Measured through the product** (1 vCPU, 1 GiB guest; 3 runs each):

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
- **Memory:** passt's RSS was 18–21 MiB, inside the VM's
  `guest RAM + overhead` limit. The cgroup peaked at 922–1074 MiB of
  1280 MiB, with no OOM.
- **Confinement:** passt ran as uid 999 under its AppArmor profile
  (`passt (enforce)`).
- **Boot without an IPv6 default route:** the VM was ready in 12 s.

## Installing on a host

This is an owner task: it needs root, and it changes the host's firewall.
Do it only after the lab gate.

**What it changes:** packets from sockets of user `stallo` only. Other
users, other services and packets without a socket are not matched (lab:
root's traffic and another table's TCP resets were unaffected). Until a
`stallo` daemon runs `internet` VMs, nothing sends as that user.

1. **Install passt:**
   - `sudo apt install passt`
   - Rollback: `sudo apt remove passt`
2. **Create the user** (the table resolves its uid when loaded):
   - `sudo useradd --system --no-create-home --shell /usr/sbin/nologin --groups kvm stallo`
   - Rollback: `sudo userdel stallo`
3. **Load the table:**
   - `sudo install -D -m 644 packaging/stallo.nft /etc/stallo/stallo.nft`
   - `sudo nft -f /etc/stallo/stallo.nft`
   - Check: `sudo nft list table inet stallo`
   - Rollback: `sudo nft delete table inet stallo && sudo rm -r /etc/stallo`
4. **Optional: keep the table across reboots.** Without this, the table is
   gone after a reboot and `internet` VMs are refused (fail closed) until
   it is loaded again. The unit is
   `/etc/systemd/system/stallo-nft.service`:

   ```
   [Unit]
   Description=Stallo network isolation table
   Before=network-pre.target
   Wants=network-pre.target

   [Service]
   Type=oneshot
   RemainAfterExit=yes
   ExecStart=/usr/sbin/nft -f /etc/stallo/stallo.nft
   ExecStop=/usr/sbin/nft delete table inet stallo

   [Install]
   WantedBy=multi-user.target
   ```

   - Enable it: `sudo systemctl daemon-reload && sudo systemctl enable --now stallo-nft`
   - Rollback: `sudo systemctl disable --now stallo-nft && sudo rm /etc/systemd/system/stallo-nft.service && sudo systemctl daemon-reload`
5. **If `nftables.service` is enabled**, a reload of `/etc/nftables.conf`
   runs `flush ruleset` and removes the table. Running `internet` VMs then
   pause within a few seconds (the probe repeats every 2 s). Add `include "/etc/stallo/stallo.nft"` at the end of
   that file to keep the table.

**After the install:**
- `internet` VMs still need `stallod` in production mode as user
  `stallo`. That service is packaged in M5. Dev mode keeps refusing
  `internet`.
- `[net] dns` in `/var/lib/stallo/stallod.toml` picks the public resolver
  for guests (default `9.9.9.9`, Quad9).
