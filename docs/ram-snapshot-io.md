# RAM snapshot images: page cache or O_DIRECT

A RAM snapshot writes the guest's RAM into `states/<name>.qcow2` and a
restore reads it back (`src/snapshot.rs`, `with_state`). The image is
attached with QMP `blockdev-add` for the job only, with QEMU's default cache
options (`cache.direct=off`, `cache.no-flush=off`, `aio=threads`). After
each job the daemon calls `posix_fadvise(DONTNEED)` on the file. This study
compares that with O_DIRECT (`cache.direct=on`) and decides which to use.

**Result: keep the page cache.** O_DIRECT is 2.7 to 4.9 times slower on
both save and restore. Its only gain is that the VM cgroup holds no page cache
during the job. The security difference is small, because the same bytes
are on disk in a 0700 directory either way.

## How QEMU writes and reads the image

These details come from QEMU 10.2 source.

- **Save** (`save_snapshot` → `qemu_savevm_state`) goes through a QEMUFile
  on a block channel (`migration/channel-block.c`). Each write calls
  `bdrv_writev_vmstate` synchronously, at queue depth 1, with the guest
  paused. A write is about 128 KiB in 64 iovecs, alternating an 8-byte page
  header with a 4 KiB guest page. Offsets and lengths are not aligned.
- **Load** reads at most 32 KiB at a time (`IO_BUF_SIZE`), also at queue
  depth 1. QEMU has no readahead of its own.
- **What O_DIRECT adds:** because the requests are unaligned, file-posix
  copies every request through a bounce buffer (`QEMU_AIO_MISALIGNED`).
  The block layer adds read-modify-write padding (`bdrv_pad_request`). The
  kernel's readahead is lost.
  - `aio=native` needs `cache.direct=on`, and it sends misaligned requests
    to the thread pool anyway.
  - `aio=io_uring` cannot be used: the QEMU seccomp filter returns ENOSYS
    for `io_uring_setup` (`src/confine.rs`), and it should stay that way.
- **Crash consistency** is the same in both modes:
  - `qemu_fclose` flushes the state node before any snapshot table is
    written (`bdrv_all_create_snapshot`).
  - `qcow2_write_snapshots` flushes before it updates the header.
  - `blockdev-del` flushes again.
  - `cache.direct=on` does not remove the need for these flushes, because
    the NVMe write cache is volatile ("write back").
  - `cache.no-flush=on` would skip every fdatasync and break this ordering
    on a host crash, so it must not be used.
  - Stallo needs no explicit fsync of its own.

## Host

| Item | Value |
|---|---|
| Kernel / QEMU | 7.0.0-34-generic / 10.2.1 |
| `/` | ext4 on LVM on NVMe; 512 B logical and physical sectors, 4 KiB minimum/optimal I/O; volatile write cache; **not encrypted** |
| Swap | 8 GiB `/swap.img` (6.1 GiB used at the time); zswap off; swappiness 60 |
| Memory init | `init_on_alloc=1`, `init_on_free` off |
| Lockdown | `integrity`, so hibernation is disabled |
| `/proc/kcore` | root only, 0400 |
| kdump | armed; the default dump level 31 leaves out page cache and free pages |

## Measurements

- **Harness:** `STALLO_IT=1 cargo test --test kvm_snapshot pause_times
  -- --ignored`. Each run uses one VM: 2 vCPU, offline, with 2 GiB and then
  4 GiB of RAM.
- **Headroom:** the run script refused to start below 4096 + 512 + 12288
  MiB `MemAvailable` (4 GiB guest, QEMU overhead, 12 GiB headroom).
  Before the runs it read 22.3–24.5 GiB (printed by the script, not in the
  test logs).
- **Jobs per run:**
  1. save while idle;
  2. save with ½ of RAM filled from `/dev/urandom`;
  3. restore;
  4. save after that restore;
  5. save with ¾ of RAM filled.
- **Memory sampling:** the test samples the VM cgroup's `memory.stat`
  (`file`, `anon`) and the host's `Cached` every 50 ms during each job, and
  once after it.
- **Restore → first exec** is timed around the API call, the sampler's
  stop (up to 50 ms) and one `exec`.
- **Runs:**
  - page cache (current code): 3 runs;
  - O_DIRECT (`"cache": {"direct": true}` on the state node): 3 runs;
  - O_DIRECT with `aio=native`: 1 run, as a check.

### Guest pause (ms): median (min–max), n = 3

| Guest | Job | Page cache | O_DIRECT | Factor |
|---|---|---|---|---|
| 2 GiB | save, idle | 825 (790–989) | 2262 (2259–2305) | 2.7× |
| 2 GiB | save, ½ RAM filled | 989 (975–1040) | 4667 (4547–4768) | 4.7× |
| 2 GiB | restore | 1399 (1352–1403) | 5260 (5125–5260) | 3.8× |
| 2 GiB | restore → first exec | 1573 (1573–1975) | 5435 (5285–5436) | 3.5× |
| 2 GiB | save after restore | 973 (952–974) | 4568 (4505–4722) | 4.7× |
| 2 GiB | save, ¾ RAM filled | 1071 (1067–1074) | 5126 (4915–5249) | 4.8× |
| 4 GiB | save, idle | 703 (631–739) | 2813 (2735–2884) | 4.0× |
| 4 GiB | save, ½ RAM filled | 1561 (1498–1567) | 7383 (7220–7441) | 4.7× |
| 4 GiB | restore | 2158 (2144–2178) | 8436 (8384–8445) | 3.9× |
| 4 GiB | restore → first exec | 2327 (2327–2376) | 8497 (8443–8594) | 3.7× |
| 4 GiB | save after restore | 1472 (1389–1513) | 7239 (7189–7404) | 4.9× |
| 4 GiB | save, ¾ RAM filled | 2119 (1985–2126) | 9776 (9757–10108) | 4.6× |

With `aio=native`, the single run came within 5% of plain O_DIRECT. For
example, with 2 GiB the ½-filled save took 4470 ms and the restore 5290 ms;
with 4 GiB they took 7120 ms and 8234 ms.

### Page cache during the job: VM cgroup `file` above its value before (MiB)

Values are median (min–max), n = 3.

| Guest | Job | Page cache: peak | Page cache: after | O_DIRECT: peak / after |
|---|---|---|---|---|
| 2 GiB | save, idle | 846 (842–850) | 0 | 0 / 0 |
| 2 GiB | save, ½ RAM filled | 329 (310–452) | −130 (−140–0) | 0 / 0 |
| 2 GiB | restore | 475 (471–482) | 0 | 0–1 / 0–1 |
| 2 GiB | save after restore | 461 (457–466) | 0 | 0 / 0 |
| 2 GiB | save, ¾ RAM filled | 254 (254–260) | 0 | 0 / 0 |
| 4 GiB | save, idle | 1040 (1039–1056) | 0–1 | 0 / 0 |
| 4 GiB | save, ½ RAM filled | 1181 (1172–1312) | −125 (−131–0) | 0 / 0 |
| 4 GiB | restore | 1356 (1344–1358) | 0–1 | 0 / 0 |
| 4 GiB | save after restore | 1318 (1305–1320) | 0 (−1–0) | 0–1 / 0–1 |
| 4 GiB | save, ¾ RAM filled | 307 (299–307) | 0 | 0–1 / 0–1 |

- **Host `Cached`** follows the cgroup's `file` within a few MiB, except
  the filled 4 GiB saves (up to about 340 MiB lower: other services freed
  cache meanwhile). No job left host page cache behind.
- **cgroup `memory.peak`:**
  - Page cache: it reached `memory.max` in every run (2304 of 2304 MiB, and
    4352 of 4352 MiB), so the kernel reclaimed inside the VM cgroup during
    the job.
  - O_DIRECT: it stayed 100–300 MiB below `memory.max`.
  - `oom_kill` was 0 in every run. The fullest guest measured had ¾ of
    its RAM faulted in; a guest with all RAM resident leaves the image's
    page cache less room and was not measured.
- **Negative "after" values:** the ½-filled saves pushed 120–140 MiB of
  the VM's other page cache out. The overlay disk uses `cache.direct=on`, so
  this is most likely the cached read-only base image, seed ISO or
  firmware (not verified); it is read back on demand. This is the main
  side effect of the page cache, and it stays inside the VM's own cgroup.

**Hybrids** need no separate run. A fresh `blockdev-add` per job can choose
its cache mode, so a hybrid is either O_DIRECT for save and page cache for
restore, or the reverse. Each side would behave like its row above. Both
hybrids are 4 to 5 times slower on the O_DIRECT side, and that side gains
nothing on security.

## Security

- **At rest:** the image holds the full guest RAM, including any secrets in
  it, on an unencrypted disk, in both modes. Only file permissions protect
  it: the VM directory tree is 0700 and the daemon's umask is 027. The cache
  mode does not change this.
- **Page cache residency:**
  - During a job, the image's pages are in the page cache. Reading them
    requires opening the file, so the same permissions apply.
  - Page-cache side channels (`mincore`, `RWF_NOWAIT`, Gruss et al. 2019)
    also need the file to be opened or mapped.
  - After the job, DONTNEED drops the pages. They are clean, because QEMU
    flushed them.
  - The measurements show 0–1 MiB left in the cgroup after every job.
- **Freed pages:**
  - With `init_on_free` off, dropped pages keep guest data until they are
    reused. `init_on_alloc` zeroes them before anyone else gets them.
  - Only root can still read freed memory, through `/proc/kcore` (lockdown
    `integrity` allows it). Root can read the image file anyway.
  - Hibernation is disabled, and kdump's default level leaves out page cache
    and free pages.
  - O_DIRECT has residue too: its bounce buffers are QEMU heap memory that
    is freed after use.
- **Swap:** page-cache pages are file-backed and are never written to swap.
  Guest RAM is never swapped either (`memory.swap.max=0`). Neither mode
  puts guest RAM into `/swap.img`.
- **Other cgroups:**
  - The page cache is charged to the VM's own cgroup, which is capped at
    `guest RAM + max(qemu_overhead_mib, guest RAM / 16)` (256 MiB by
    default up to 4 GiB guests).
  - The job cannot grow the VM's memory use beyond that cap, which
    admission already reserves. Up to that cap (here up to 1.3 GiB, partly
    dirty until the flush) it is still real host memory and adds to global
    pressure; this host is sometimes in global reclaim (swap 6 of 8 GiB in
    use), where Jarvis and Rivetlink would share it.
  - Reclaim at the cap touches only file pages (no swap), and every run
    finished without an OOM kill.
- **Disk I/O:** both modes write the same bytes, with a different profile:
  the page cache sends a 0.6–2.1 s full-bandwidth burst and one large
  fdatasync; O_DIRECT a 2–10 s queue-depth-1 trickle. The latency effect on
  other services' I/O was not measured.

## Recommendation

- **Keep the page cache, unchanged.** It pauses the guest 2.7–4.9× less on
  save and restore. Its page cache is bounded by the VM's own cgroup and dropped
  after each job, and it carries the same data-at-rest exposure as O_DIRECT.
- **Nothing is missing:**
  - QEMU already flushes in the right order, so no explicit fsync is needed.
  - DONTNEED already runs after both save and restore.
  - `pause_times` now asserts that every job leaves no page cache behind in
    the VM cgroup.
- **Out of scope** (security, not cache mode): the RAM images are plaintext
  guest memory on an unencrypted disk. Encrypting `/`, or the qcow2 images
  with LUKS, is the real fix if that matters.
