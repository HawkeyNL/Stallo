# Production mode: the package, the service and the M5 gate

Production mode runs `stallod` as the system user `stallo` under
`stallod.service`, with data in `/var/lib/stallo` and runtime files in
`/run/stallo`. It is the only mode that offers the `internet` network
profile (see [network-verification.md](network-verification.md)). This
document covers the package, the systemd hardening and the evidence for it,
the M5 lab gate, and the owner's install and rollback steps.

## The package

`packaging/build-deb.sh` builds `target/deb/stallo_<version>_amd64.deb` from
a release build with `dpkg-deb` (no root, no extra tools).

| Path | What |
|---|---|
| `/usr/bin/stallo`, `/usr/bin/stallod` | the CLI and the daemon |
| `/usr/lib/systemd/system/stallod.service` | the daemon (`packaging/stallod.service`) |
| `/usr/lib/systemd/system/stallo-nft.service` | loads the network table at boot (`packaging/stallo-nft.service`) |
| `/etc/apparmor.d/stallo-qemu` | QEMU's AppArmor profile (`packaging/apparmor/stallo-qemu`), a conffile |
| `/etc/stallo/stallo.nft` | the table (`packaging/stallo.nft`), a conffile: local edits such as a LAN IPv6 prefix in `deny6` survive upgrades |

**Depends:** `apparmor`, `nftables`, `passt`, `qemu-system-x86 (>= 1:10.2)`,
`qemu-utils`, `ovmf`, `xorriso`, `curl`, `gpgv`,
`ubuntu-cloudimage-keyring`, `passwd` (`useradd`), and `systemd (>= 257)`
(older versions ignore `ProtectControlGroups=private`).

**Maintainer scripts:**

- **postinst:**
  - Creates the system user `stallo` (group `stallo`, home
    `/var/lib/stallo`, shell `nologin`) if it does not exist.
  - Refuses to continue if `stallo` exists but is a human account
    (uid 0 or ≥ 1000): the table and the daemon would then apply to it.
  - Refuses to continue if a group `stallo` exists without the user: its
    members would get the full API. At the end it prints the group's
    members.
  - The user is not added to group `kvm`; the unit grants `/dev/kvm`
    (`SupplementaryGroups=kvm`).
  - Enables both units on first install, and keeps the owner's choice on
    upgrades.
  - Loads QEMU's AppArmor profile (if AppArmor is enabled), the table
    (`restart stallo-nft`), then starts `stallod`. It
    does the same when dpkg rolls a failed upgrade back
    (`abort-upgrade`), so the daemon that prerm stopped comes back.
- **prerm:** stops `stallod`. **That stops every VM**, on upgrade and
  removal alike: VMs live in the daemon's cgroup.
- **postrm remove:** deletes the table (nothing runs as `stallo` any more),
  unloads QEMU's AppArmor profile, and masks the units, as debhelper does.
  - It never deletes VMs, images, `/var/lib/stallo` or the user, not even
    on purge. The steps below remove them by hand.

**`stallo-gui`:** `packaging/build-gui-deb.sh` builds
`target/deb/stallo-gui_<version>_amd64.deb`, the desktop app (an early
preview). Building it needs `libgtk-4-dev`, `libadwaita-1-dev` and
`pkg-config`. It holds
`/usr/bin/stallo-gui` (stripped, size budget 15 MB), the desktop file, the
icons and the AppStream metadata, and has no maintainer scripts.
**Depends:** `stallo (= <version>)`, `libgtk-4-1 (>= 4.16)`,
`libadwaita-1-0 (>= 1.7)`, `libglib2.0-0t64`, `libgcc-s1`, `libc6`. The
script fails if the binary links a library from any other package
(`objdump -p`, `dpkg -S`).

**Why not `cargo-deb`** (as the plan said): it is not installed here, and
installing tools needs the owner's approval. `dpkg-deb` is part of every
Ubuntu system, and the package is small enough to build by hand.

## API access

- `/run/stallo` is `0750` and `api.sock` is `0660`, both group `stallo`.
  The per-VM directories below stay `0700`, so QMP and QGA sockets remain
  private to the daemon (S3).
- The daemon accepts its own uid, root, and members of its group. It reads
  the peer's supplementary groups with `SO_PEERGROUPS` (S2).
- **Every member of group `stallo` has the full API**, the same as the
  owner. Add only trusted users.
- The CLI uses `/run/stallo/api.sock` when it exists and the user can
  reach it, else the dev-mode socket. `--socket` and `$STALLO_SOCKET`
  override both.

## The service unit

`systemd-analyze security stallod`: **2.3** (gate: ≤ 2.5), measured in the
lab on the installed unit. Every setting below was in place for the whole
gate.

| Setting | Why |
|---|---|
| `User=stallo`, `Group=stallo`, `SupplementaryGroups=kvm` | the table matches this user; `/dev/kvm` through the group |
| `Delegate=cpu memory pids` | the daemon writes the VM cgroups itself |
| `CPUWeight=50`, `IOWeight=50` | host services win under contention |
| `KillMode=mixed`, `TimeoutStopSec=120` | stopping the unit powers every VM off, see below |
| `Restart=on-failure`, `RestartSec=5s` | a crashed daemon comes back; its VMs died with it and stay stopped |
| `StateDirectory=` (0700), `RuntimeDirectory=` (0750), `UMask=0027` | see API access |
| `NoNewPrivileges`, `CapabilityBoundingSet=` (empty) | no privileges at all |
| `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp` | writes only to its own directories |
| `PrivateDevices=yes`, `BindPaths=/dev/kvm`, `DevicePolicy=closed`, `DeviceAllow=/dev/kvm rw` | a private `/dev` with `/dev/kvm` only |
| `ProtectControlGroups=private` | a cgroup namespace rooted at the unit, writable for the delegated tree |
| `ProtectProc=invisible` | other users' processes are hidden |
| `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK` | passt and image downloads |
| `RestrictNamespaces=user mnt ipc uts pid` | passt's own sandbox |
| `SystemCallFilter=@system-service @mount seccomp landlock_*` | see below |
| `MemoryDenyWriteExecute`, `LockPersonality`, `RestrictRealtime`, `RestrictSUIDSGID`, `RemoveIPC`, `ProtectKernel*`, `ProtectClock`, `ProtectHostname`, `SystemCallArchitectures=native` | standard hardening; QEMU (KVM, no TCG) and passt run fine with them |

**Measured in the lab, not assumed:**

- **`ProtectControlGroups` and `Delegate`** (an open question in the plan):
  - `yes` makes `/sys/fs/cgroup` read-only, the delegated subtree too, so
    the daemon could not create VM cgroups.
  - `private` gives the unit its own cgroup namespace with a writable
    `/sys/fs/cgroup`. The daemon sees `0::/daemon` in `/proc/self/cgroup`,
    and its `/sys/fs/cgroup` shows only its own subtree (no
    `system.slice`). The code needed no change: it already resolves its
    cgroup through `/proc/self/cgroup`.
  - `systemd-analyze security` counts `private` as protected.
- **passt needs `@mount` and the PID namespace.** With either one removed
  (a drop-in without `@mount`, or `RestrictNamespaces=user mnt ipc uts`),
  `stallo new --net internet` failed: `passt exited (exit status: 1)`.
  passt uses its own user, mount, IPC and UTS namespaces (seen in
  `/proc/<passt>/ns`) and pivots into an empty root.
- **`KillMode=mixed`, not `control-group`** (the plan's choice).
  - With `control-group`, systemd sends SIGTERM to every process in the
    unit at once. QEMU exits on it (`terminating on signal 15 from pid 1`
    in `qemu.log`), so the guests lose power before the daemon can shut
    them down.
  - With `mixed`, only the daemon gets SIGTERM. A booted guest powered
    off over ACPI in 3.3 s, and QEMU logged no signal.
  - The daemon's stop takes at most 110 s, inside `TimeoutStopSec=120`:
    up to 30 s for requests in flight, then up to 80 s for the VMs (ACPI
    power-off for 60 s, then `quit`, then `cgroup.kill`). A VM whose
    lifecycle lock stays held (a long snapshot job, `stallo run`) is
    killed when the 80 s run out. systemd kills whatever is left when
    the daemon exits.
- **`seccomp` and `landlock_*`** are not in `@system-service`, and the
  daemon needs them to confine every QEMU (`src/confine.rs`).
- **`MemoryDenyWriteExecute`** is inherited by QEMU and passt: QEMU with
  KVM does not generate code, and every VM in the gate ran with it.
- **Not used, and why:**
  - `PrivateUsers`: it would drop group `kvm`.
  - `PrivateNetwork` and `IPAddressDeny`: guests need the internet. The
    nftables table does the filtering, and the probe checks it.
  - `ProcSubset=pid`: the daemon reads `/proc/meminfo` for admission.

**AppArmor.**

- **passt:** it runs under Ubuntu's `passt` profile (`passt (enforce)`)
  and works unchanged: it gets its socket with `--fd`.
  - The only denial is passt's syslog socket, as in M3; passt logs to
    stderr instead.
- **QEMU (M5-3):** the package ships the profile `stallo-qemu`
  (`/etc/apparmor.d/stallo-qemu`, a conffile; `packaging/apparmor/`) and
  postinst loads it.
  - In production the daemon makes every QEMU enter it at exec
    (`/proc/self/attr/apparmor/exec`, as `aa_change_onexec` does). The
    guest's CPUs stay stopped (`-S`) until the checks below pass.
  - After QMP answers, it checks QEMU's label and kills the VM unless it is
    the profile in enforce mode. It checks again every 10 s (with the disk
    watchdog), so a profile reloaded in complain mode kills the VMs.
    **Without the profile, VMs do not start** (fail closed); the gate
    tests that.
  - Started by user `stallo`, the profile is stacked on `unconfined`: the
    label reads `stallo-qemu//&unconfined (enforce)`, and the rules in
    force are the profile's. Measured in the lab: as root the label is
    plain `stallo-qemu (enforce)` with or without `no_new_privs`; as user
    `stallo` it is stacked either way. Both forms are accepted.
  - The profile allows Stallo's **files** below `/var/lib/stallo` and
    `/run/stallo`, `/usr/share/{qemu,seabios,OVMF}` and `/dev/kvm`. It
    denies, and logs (`audit deny`), the network, capabilities, ptrace,
    mount, `connect` on Unix sockets and binding abstract ones.
  - It is one profile for all VMs. At the AppArmor layer a QEMU could
    still reach another VM's sockets and signal its QEMU; the per-VM
    Landlock ruleset (files, signals) and the seccomp filter (`connect`)
    stop that.
  - **No `stallo-qemu` denial** was logged during the whole gate, which
    includes VNC, port forwards and RAM snapshots.
  - Dev mode does not use the profile: its paths are under `$HOME`, and
    loading a profile needs root.
  - Removing the package unloads the profile; the conffile stays until
    purge, so `apparmor.service` loads it again at boot (harmless: it
    attaches to nothing by itself).
- **swtpm:** not used before M4 (Windows).
- **No override of Ubuntu's profiles is needed.**

## M5 gate (lab VM)

`tests/lab/m5-production.sh` runs the gate inside the lab VM. Like the M3
script, it refuses to run without `/etc/stallo-lab` and outside a VM.

- It installs the `.deb` with `apt-get` from a local apt source in the lab,
  so the package's dependencies are resolved for real.
- It runs the S-checks against the packaged daemon, then
  `m3-network.sh` (S14, S15) against it, then stop, upgrade, removal and
  reinstall.

**The lab:**

- Ubuntu 26.04 cloud image, 2 vCPU, 3 GiB, `-nic none`, nested KVM.
- Nested guests: 1 vCPU, 1 GiB.
- Packages: fetched on the host with `apt-get download` (checked against
  apt's signed index) and served to the lab from a read-only ISO.
- The host only ran this one offline VM.

**Result: all 114 checks passed** in a freshly installed lab VM, with
the package built from this branch. With VNC (M5-4) and the QEMU AppArmor
profile (M5-3) on top, the same gate grew to **127 checks, all passed**.
The final run, on the whole stack (with remote MCP, M5-2) after every
review fix, passed **all 147 checks** on a fresh lab VM.

| Check | Result |
|---|---|
| Install with `apt-get`: user `stallo` (nologin, home `/var/lib/stallo`), both units enabled and active, table loaded, `stallo.nft` a conffile | PASS |
| S18: `systemd-analyze security stallod` | **2.3** (≤ 2.5) |
| The daemon: uid `stallo`, no capabilities, `NoNewPrivs`, delegated `cpu memory pids`, its own cgroup namespace | PASS |
| A restart and a reload of `nftables.service` (which flush the ruleset) load the Stallo table again | PASS |
| Guest-agent packages pulled under the unit (`apt-get download` as `stallo`) | PASS |
| S1: no TCP or UDP socket of `stallod` | PASS |
| S2: `api.sock` `0660` and `/run/stallo` `0750`; a supplementary member of `stallo` uses the API; a non-member is refused by the file permissions, and, given access through an ACL, by the daemon's group check (logged); the CLI picks the production socket | PASS |
| S3: per-VM runtime dir `0700`; a group member cannot connect to QMP; data dir `0700` | PASS |
| S4: `-sandbox …spawn=deny…`, `-nodefaults`, `-nic none`, no `-vnc`; QEMU has `NoNewPrivs` and seccomp | PASS |
| S7: bad VM name and snapshot name refused | PASS |
| S8: MCP `exec` refused while agent control is off, audited as `via: mcp` | PASS |
| S11: exec timeout (killed in the guest), output cap | PASS |
| S12: over-budget VM refused; `memory.max`, `memory.swap.max = 0`, `pids.max`, `cpu.max` set; a limit below QEMU's usage OOM-kills QEMU in `vm-box` only, the daemon survives, the VM shows `stopped` | PASS |
| S13: data disk filled below the floor → `paused (disk full)`; resume after freeing space | PASS |
| S16: `secret` `0600`; not in `stallo info`, not in MCP `vm_info` | PASS |
| S14, S15: `m3-network.sh` against the packaged daemon (47 checks, including the 13 positive controls, port forwards, RAM snapshot with passt, the table removed at runtime) | PASS |
| VNC (M5-4, run with #34 in the 127-check gate): `/run/stallo/vnc/<vm>/vnc.sock` `0660` in a `0750` dir; a group member gets the RFB greeting, a non-member cannot connect; QEMU has `-vnc unix:` only and no TCP/UDP socket; an MCP `set_vnc` is refused; stop removes the dir; `--vnc off` removes `-vnc` | PASS |
| AppArmor (M5-3): QEMU runs as `stallo-qemu//&unconfined (enforce)`; with the profile unloaded a start is refused; it starts again after a reload; no `stallo-qemu` denial in the kernel log for the whole gate | PASS |
| Remote MCP (M5-2): `--http` on `0.0.0.0` or a LAN address and a world-readable token file are refused; the listener is the CLI process on `127.0.0.1` only, `stallod` still has no IP socket; no token or a wrong one gets 401, a foreign `Host` or any `Origin` 403; with the token, `initialize` works, `exec` is refused while agent control is off and works when on, audited as `via: mcp` with the caller's uid; a burst of wrong tokens hits its own 5/s budget (429) while the agent still gets 200; 30 quick requests on one connection get 20 × 200 and 10 × 429; on a Tailscale-class address, a LAN peer reaching it through the weak host model gets no HTTP answer and is logged | PASS |
| Stop with a running VM: the guest powers off over ACPI (3.5 s), QEMU gets no signal, no process of `stallo` is left | PASS |
| Upgrade (`--reinstall`): VMs stopped, daemon back, table loaded | PASS |
| `apt remove`: no process left, table deleted, VM data and user kept; reinstall brings everything back | PASS |

- **S12, how the OOM kill was forced.** A guest alone cannot push QEMU
  past its limit (guest RAM plus overhead), and its RAM is already backed
  after boot. So the gate lowers `memory.max` below QEMU's anonymous
  memory. With no swap, the kernel kills QEMU (`oom_memcg=…/vm-box`), and
  nothing else.
- **The lab disk uses `cache=none`.** With the host page cache, a full run
  stalled the lab VM during the RAM snapshot: the snapshot's writes were
  charged to the lab's 3.7 GiB memory cgroup on the host.

**S-checks that do not depend on the mode** run as unit tests on every
`cargo test` and in CI: S5 (image formats), S6 (`safe_remove`), S9
(audit redaction), S10 (oversized QGA/QMP replies). S17 is CI
(`cargo deny`). S2 also has a unit test for `authorize` and one for
`SO_PEERGROUPS`.

**Not verified:**

- **The image download** (`curl` to cloud-images.ubuntu.com) under the
  unit: the lab is offline.
  - The guest-agent download (`apt-get download`) did run under the unit,
    from the lab's local apt source.
  - DNS for both goes through `127.0.0.53`, which the table allows for
    the daemon.
- **A reboot of a host with the package installed.** The units are
  enabled, and the lab was not rebooted after the install.

## Installing on the host (owner)

This needs root and changes the host: a new system user, a firewall table
and a service. It touches no other service. Rivetlink and PersonalJarvis
keep running, and the table matches only packets of user `stallo`.

**Before you start (read-only):**

1. The checks in [network-verification.md](network-verification.md),
   "Check the host first": global IPv6 on the LAN, and whether your
   router answers on its public address.
2. `getent passwd stallo; getent group stallo`: both empty (on
   2026-10-14 they were).
3. `systemctl is-enabled nftables`: `nftables.service` runs
   `flush ruleset` on start, stop, restart and reload, which removes the
   Stallo table too. Running `internet` guests then lose their network
   until they restart.
   - `stallo-nft.service` follows a restart or reload of `nftables`
     (`PartOf=`, `ReloadPropagatedFrom=`) and loads the table again.
   - After a plain start of `nftables`, or a stop and start, run
     `sudo systemctl restart stallo-nft`.
   - It was `disabled` on 2026-10-14.
4. Nothing from the manual M3 steps: `/etc/systemd/system/stallo-nft.service`
   would override the packaged unit, and an existing
   `/etc/stallo/stallo.nft` makes dpkg ask about the conffile. On
   2026-10-14 neither existed (and the user did not either).
5. Memory: the production daemon admits VMs against its own budget
   (`memory_budget_pct`, default 50% of RAM), independent of a dev-mode
   daemon. Do not run VMs in both at once without lowering one budget.

**Steps.** Each step has its rollback; to undo everything, run the
rollbacks in reverse order.

1. **Build the package** (as your user, no root):
   - `cd ~/projects/Stallo && packaging/build-deb.sh`
   - Inspect it: `dpkg-deb -I target/deb/stallo_0.1.0_amd64.deb` and
     `dpkg-deb -c target/deb/stallo_0.1.0_amd64.deb`
   - Rollback: `rm -r target/deb`
2. **Install:**
   - `sudo apt install ./target/deb/stallo_0.1.0_amd64.deb`
     - This also installs `passt` and `ubuntu-cloudimage-keyring`; the
       other dependencies are already installed.
   - What it does: creates user and group `stallo`, loads the table and
     QEMU's AppArmor profile, enables and starts `stallo-nft.service` and
     `stallod.service`.
   - Rollback: `sudo apt remove stallo`
     - It stops the daemon (and every VM), deletes the table and unloads
       the AppArmor profile.
     - It keeps `/var/lib/stallo` and the user (step 6).
     - `sudo apt remove passt ubuntu-cloudimage-keyring` removes the two
       new dependencies, if nothing else needs them.
3. **Check:**
   - `systemctl status stallod stallo-nft`: both active.
   - `sudo systemd-analyze security stallod`: ≤ 2.5.
   - `sudo nft list table inet stallo`: shows the table.
   - The functional checks from network-verification.md, step 4:
     - `sudo -u stallo curl -m 3 http://<router>/` fails;
     - `sudo -u stallo curl -sI -m 5 https://example.com` works;
     - your own `curl http://<router>/` still works.
4. **Give your user access:**
   - `sudo usermod -aG stallo $USER`, then log in again (or `newgrp stallo`).
   - `stallo ls` now talks to the production daemon.
   - Rollback: `sudo gpasswd -d $USER stallo`. This only affects new
     logins: running sessions, tmux and user services keep the group
     until they end, so log out completely.
   - The CLI refuses to guess when both a production and a dev-mode
     daemon run: pass `--socket` or set `STALLO_SOCKET`.
5. **Optional, configure:** `/var/lib/stallo/stallod.toml`.
   - Keys: `[host]` `memory_budget_pct`, `reserve_mib`, `disk_floor_gib`,
     `reserved_cores`, and `[net] dns`.
   - Edit it with `sudoedit -u stallo /var/lib/stallo/stallod.toml`.
   - Then `sudo systemctl restart stallod`. **This stops all VMs.**
   - Rollback: delete the file and restart (the defaults apply).
6. **Full removal**, only if you also want to delete all VMs and images:
   - `sudo apt purge stallo`
   - `sudo rm -r /var/lib/stallo`: **deletes every VM disk and snapshot**.
   - `sudo userdel stallo`, then `sudo groupdel stallo` if the group is
     still there.

**Upgrades:** `sudo apt install ./target/deb/stallo_<new>_amd64.deb`. The
upgrade stops the daemon and every VM, then starts the new daemon. The VMs
stay defined (`stopped`); start them again with `stallo start`.
