#!/bin/sh
# M5 gate: the .deb in production mode.
#
# LAB VM ONLY. It installs and removes the package, creates users, loads
# nftables rules and fills the disk, so it refuses to run unless
# /etc/stallo-lab exists and this is a VM. Never run it on a real host.
#
# Needs in the lab VM: an apt source with the package's dependencies, the
# packages of tests/lab/m3-network.sh, python3, and
#   $DEB     the stallo .deb (packaging/build-deb.sh)
#   $IMAGES  directory with ubuntu-26.04.qcow2 and debs/26.04/*.deb
#
# Checks: install, S18 (systemd hardening), S1-S4, S7, S8, S11-S13, S16 on
# an offline VM, then S14/S15 with m3-network.sh against the packaged
# daemon, then stop, upgrade and removal. Prints PASS/FAIL per check and
# exits non-zero on any failure.
set -eu
[ "$(id -u)" = 0 ] || { echo "run as root (inside the lab VM)"; exit 2; }
[ -e /etc/stallo-lab ] || { echo "refusing: /etc/stallo-lab is missing; this is not a lab VM"; exit 2; }
systemd-detect-virt --vm -q || { echo "refusing: not a virtual machine"; exit 2; }
: "${DEB:?}" "${IMAGES:?}"
HERE=$(cd "$(dirname "$0")" && pwd)
CG=/sys/fs/cgroup/system.slice/stallod.service
fails=0
pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; fails=$((fails + 1)); }
check() { name=$1; shift; if "$@" >/dev/null 2>&1; then pass "$name"; else fail "$name"; fi; }
refused() {
	name=$1 want=$2; shift 2
	if out=$("$@" 2>&1); then fail "$name (succeeded)"
	elif echo "$out" | grep -q "$want"; then pass "$name"
	else fail "$name ($out)"; fi
}
as() { u=$1; shift; runuser -u "$u" -- "$@"; }
qemu_pid() { pgrep -u stallo -f "qemu-system-x86_64 -name guest=$1," | head -n 1; }
wait_sock() { for _ in $(seq 50); do [ -S /run/stallo/api.sock ] && return 0; sleep 0.2; done; return 1; }
# One MCP tool call over `stallo mcp` as user $1; prints the JSON-RPC reply.
mcp() {
	u=$1 tool=$2 args=$3
	{
		echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"lab","version":"0"}}}'
		echo '{"jsonrpc":"2.0","method":"notifications/initialized"}'
		echo "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"$tool\",\"arguments\":$args}}"
		sleep 3
	} | as "$u" stallo mcp | grep '"id":2'
}

install_pkg() {
	echo "== install"
	DEBIAN_FRONTEND=noninteractive apt-get install -y "$DEB" >/dev/null
	check "user stallo, no login, home /var/lib/stallo" sh -c 'getent passwd stallo | grep -q ":/var/lib/stallo:/usr/sbin/nologin$"'
	check "stallo-nft enabled and active" sh -c 'systemctl is-enabled -q stallo-nft && systemctl is-active -q stallo-nft'
	check "stallod enabled and active" sh -c 'systemctl is-enabled -q stallod && systemctl is-active -q stallod'
	check "table inet stallo loaded" nft list table inet stallo
	check "/etc/stallo/stallo.nft is a conffile" sh -c 'dpkg-query -W -f="\${Conffiles}" stallo | grep -q /etc/stallo/stallo.nft'
}

configure() {
	echo "== configure (lab sizes, offline image cache)"
	install -d -o stallo -g stallo -m 700 /var/lib/stallo/images /var/lib/stallo/images/debs
	install -o stallo -g stallo -m 444 "$IMAGES/ubuntu-26.04.qcow2" /var/lib/stallo/images/
	cp -r "$IMAGES/debs/26.04" /var/lib/stallo/images/debs/ && chown -R stallo:stallo /var/lib/stallo/images/debs
	cat >/var/lib/stallo/stallod.toml <<-'EOF'
		[host]
		memory_budget_pct = 60
		reserve_mib = 256
		disk_floor_gib = 2
		reserved_cores = 1
		[net]
		dns = "198.51.100.1"
	EOF
	chown stallo:stallo /var/lib/stallo/stallod.toml
	systemctl restart stallod
	wait_sock || { journalctl -u stallod --no-pager | tail; exit 1; }
	# labuser may use Stallo (supplementary group), outsider may not.
	id labuser >/dev/null 2>&1 || useradd --create-home --groups stallo labuser
	id outsider >/dev/null 2>&1 || useradd --create-home outsider
}

service_checks() {
	echo "== S18 and the unit"
	score=$(systemd-analyze security stallod --no-pager | sed -n 's/.*stallod.service: \([0-9.]*\).*/\1/p')
	echo "systemd-analyze security stallod: $score"
	check "S18: exposure $score <= 2.5" awk "BEGIN { exit !($score <= 2.5) }"
	pid=$(systemctl show -p MainPID --value stallod)
	check "daemon runs as stallo" sh -c "[ \"\$(stat -c %U /proc/$pid)\" = stallo ]"
	check "daemon has no capabilities" grep -q '^CapEff:	0000000000000000$' /proc/"$pid"/status
	check "daemon has NoNewPrivs" grep -q '^NoNewPrivs:	1$' /proc/"$pid"/status
	check "daemon cgroup is delegated (cpu memory pids)" sh -c "[ \"\$(cat $CG/cgroup.subtree_control)\" = 'cpu memory pids' ]"
	# nftables.service runs `flush ruleset` on start, restart and reload.
	# systemctl returns before the propagated stallo-nft job has run.
	table_back() { for _ in $(seq 25); do nft list table inet stallo >/dev/null 2>&1 && return 0; sleep 0.2; done; return 1; }
	systemctl restart nftables
	check "table reloaded after an nftables restart" table_back
	systemctl reload nftables
	check "table reloaded after an nftables reload" table_back
	systemctl stop nftables
	systemctl restart stallo-nft
	# ProtectControlGroups=private: a cgroup namespace rooted at the unit.
	check "daemon's cgroup namespace is rooted at the unit" sh -c "nsenter -t $pid -C cat /proc/$pid/cgroup | grep -qx '0::/daemon'"
	check "daemon's /sys/fs/cgroup shows only its subtree" sh -c "nsenter -t $pid -m test -d /sys/fs/cgroup/daemon && ! nsenter -t $pid -m test -e /sys/fs/cgroup/system.slice"
}

vm_checks() {
	echo "== image pull under the unit (apt-get download from the lab's apt source)"
	mv /var/lib/stallo/images/debs/26.04 /var/lib/stallo/images/debs-26.04.seeded
	check "pull of the guest-agent packages as stallo" stallo images pull ubuntu-26.04
	check "pulled the same packages" sh -c '[ "$(ls /var/lib/stallo/images/debs/26.04)" = "$(ls /var/lib/stallo/images/debs-26.04.seeded)" ]'
	rm -rf /var/lib/stallo/images/debs-26.04.seeded

	echo "== offline VM in production mode"
	stallo new box --cpus 1 --mem 1G --disk 5G >/dev/null
	check "CLI default socket is /run/stallo/api.sock" sh -c 'stallo ls | grep -q "^box"'
	pid=$(qemu_pid box)
	check "QEMU runs as stallo in vm-box" sh -c "[ \"\$(stat -c %U /proc/$pid)\" = stallo ] && grep -qx '0::/system.slice/stallod.service/vm-box' /proc/$pid/cgroup"

	echo "== S1: no IP listener"
	check "S1: stallod has no TCP/UDP socket" sh -c '! ss -H -tuanp | grep -q "\"stallod\""'

	echo "== S2: socket access"
	check "S2: api.sock is 0660 stallo:stallo" sh -c '[ "$(stat -c "%a %U %G" /run/stallo/api.sock)" = "660 stallo stallo" ]'
	check "S2: /run/stallo is 0750" sh -c '[ "$(stat -c %a /run/stallo)" = 750 ]'
	check "S2: group member (supplementary) may use the API" as labuser stallo ls
	refused "S2: non-member is refused" "ermission denied" as outsider stallo --socket /run/stallo/api.sock ls
	refused "S2: non-member does not get the production socket by default" "XDG_RUNTIME_DIR" as outsider stallo ls
	# Past the file permissions: the daemon's own group check must refuse.
	setfacl -m u:outsider:x /run/stallo
	setfacl -m u:outsider:rw /run/stallo/api.sock
	since=$(date '+%Y-%m-%d %H:%M:%S')
	refused "S2: daemon refuses a non-member that can reach the socket" "without an answer\|Connection reset" as outsider stallo --socket /run/stallo/api.sock ls
	check "S2: the refusal is logged" sh -c "journalctl -u stallod --no-pager --since '$since' | grep -q 'refused API peer uid $(id -u outsider)'"
	setfacl -b /run/stallo/api.sock /run/stallo

	echo "== S3: per-VM runtime dir"
	check "S3: vms/box is 0700 stallo" sh -c '[ "$(stat -c "%a %U" /run/stallo/vms/box)" = "700 stallo" ]'
	check "S3: QMP socket unreachable for a group member" sh -c "! runuser -u labuser -- python3 -c 'import socket; socket.socket(socket.AF_UNIX).connect(\"/run/stallo/vms/box/qmp.sock\")'"
	check "S3: data dir is 0700" sh -c '[ "$(stat -c %a /var/lib/stallo)" = 700 ]'

	echo "== S4: QEMU argv"
	argv=$(tr '\0' ' ' </proc/"$pid"/cmdline)
	check "S4: -sandbox with spawn=deny" sh -c "echo '$argv' | grep -q -- '-sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny'"
	check "S4: -nodefaults and -nic none" sh -c "echo '$argv' | grep -q -- '-nodefaults' && echo '$argv' | grep -q -- '-nic none'"
	check "S4: no -vnc" sh -c "! echo '$argv' | grep -q -- '-vnc'"
	check "S4: QEMU has NoNewPrivs and seccomp" sh -c "grep -q '^NoNewPrivs:	1' /proc/$pid/status && grep -q '^Seccomp:	2' /proc/$pid/status"

	echo "== M5-3: QEMU AppArmor profile"
	# Changing profile from unconfined as a non-root user stacks it on
	# `unconfined`; the effective rules are the profile's.
	check "QEMU runs under stallo-qemu (enforce)" grep -qxE 'stallo-qemu(//&unconfined)? \(enforce\)' /proc/"$pid"/attr/apparmor/current
	stallo stop box >/dev/null
	apparmor_parser -R /etc/apparmor.d/stallo-qemu
	refused "start refused without the profile (exec refused)" "cannot start QEMU (is the AppArmor profile stallo-qemu loaded?)" stallo start box
	apparmor_parser -r -W /etc/apparmor.d/stallo-qemu
	check "start with the profile loaded again" stallo start box

	echo "== S7: names and tags"
	refused "S7: bad VM name" "invalid VM name" stallo new 'Bad!' --cpus 1 --mem 1G
	refused "S7: bad snapshot tag" "invalid snapshot name" stallo snap box 'bad tag!'

	echo "== S8: agent control off by default"
	r=$(mcp labuser exec '{"vm":"box","argv":["true"]}')
	check "S8: MCP exec refused while agent control is off" sh -c "echo '$r' | grep -q 'agent control is off'"
	check "S8: refusal is audited as via mcp" sh -c 'tail -n 1 /var/lib/stallo/audit/box.jsonl | grep -q "\"via\":\"mcp\""'

	echo "== S16: secrets"
	check "S16: secret is 0600 stallo" sh -c '[ "$(stat -c "%a %U" /var/lib/stallo/vms/box/secret)" = "600 stallo" ]'
	secret=$(cat /var/lib/stallo/vms/box/secret)
	check "S16: ls --json does not contain the secret" sh -c "stallo --json ls | grep -q '\"box\"' && ! stallo --json ls | grep -qF '$secret'"
	stallo agent box on
	r=$(mcp labuser vm_info '{"vm":"box"}')
	check "S16: MCP vm_info does not contain the secret" sh -c "echo '$r' | grep -q '\"result\"' && ! echo '$r' | grep -qF '$secret'"
	stallo agent box off

	echo "== S11: exec limits"
	t0=$(date +%s)
	refused "S11: exec timeout" "timed out" stallo exec --timeout 2 box -- sleep 60
	check "S11: timeout took < 10 s" sh -c "[ \$(( \$(date +%s) - $t0 )) -lt 10 ]"
	check "S11: the guest process was killed" stallo exec box -- sh -c '! pgrep -x sleep'
	check "S11: output is capped" sh -c 'stallo exec box -- head -c 3000000 /dev/zero 2>&1 >/dev/null | grep -q "output truncated"'

	echo "== S12: admission and limits"
	refused "S12: over-budget VM refused" "memory" stallo new huge --cpus 1 --mem 64G --disk 5G
	check "S12: memory.max set" sh -c "[ \"\$(cat $CG/vm-box/memory.max)\" -gt 1073741824 ]"
	check "S12: swap off, pids and cpu capped" sh -c "[ \"\$(cat $CG/vm-box/memory.swap.max)\" = 0 ] && [ \"\$(cat $CG/vm-box/pids.max)\" = 512 ] && [ \"\$(cat $CG/vm-box/cpu.max)\" = '100000 100000' ]"
	# A guest alone cannot push QEMU past its limit (guest RAM + overhead),
	# and the guest's RAM is already backed after boot. So lower the limit
	# below QEMU's anonymous memory: without swap the kernel must OOM-kill,
	# and it may only kill inside vm-box.
	since=$(date '+%Y-%m-%d %H:%M:%S')
	anon=$(awk '$1 == "anon" { print $2 }' "$CG/vm-box/memory.stat")
	echo $((anon - (64 << 20))) >"$CG/vm-box/memory.max" || true
	for _ in $(seq 20); do
		journalctl -k --no-pager --since "$since" >/tmp/m5-kern.log
		grep -q 'Killed process' /tmp/m5-kern.log && break
		sleep 0.5
	done
	check "S12: QEMU OOM-killed in vm-box" grep -q 'oom_memcg=/system.slice/stallod.service/vm-box,.*task=qemu-system-x86' /tmp/m5-kern.log
	check "S12: nothing else was OOM-killed" sh -c '[ "$(grep -c "Killed process" /tmp/m5-kern.log)" = 1 ] && ! grep "oom-kill:" /tmp/m5-kern.log | grep -qv "oom_memcg=/system.slice/stallod.service/vm-box,"'
	check "S12: the daemon survived" sh -c 'systemctl is-active -q stallod && stallo ls >/dev/null'
	for _ in $(seq 25); do stallo ls | grep -q '^box .*stopped' && break; sleep 0.2; done
	check "S12: the VM is stopped" sh -c 'stallo ls | grep -q "^box .*stopped"'

	echo "== S13: disk watchdog"
	stallo start box >/dev/null
	free=$(df --output=avail -B1 /var/lib/stallo | tail -n 1)
	fallocate -l $((free - (1 << 30))) /var/tmp/fill
	paused=
	for _ in $(seq 30); do stallo ls | grep -q 'paused (disk full)' && { paused=1; break; }; sleep 1; done
	rm -f /var/tmp/fill
	[ -n "$paused" ] && pass "S13: VM paused below the floor" || fail "S13: VM paused below the floor"
	check "S13: resume after freeing space" stallo resume box
	check "S13: the guest runs again" stallo exec box -- true
	echo "== VNC on a Unix socket (M5-4)"
	stallo stop box >/dev/null
	check "set --vnc on" stallo set box --vnc on
	stallo start box >/dev/null
	vnc=/run/stallo/vnc/box/vnc.sock
	rfb="import socket,sys; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); assert s.recv(12).startswith(b'RFB ')"
	check "VNC socket 0660 stallo:stallo, dir 0750" sh -c "[ \"\$(stat -c '%a %U %G' $vnc)\" = '660 stallo stallo' ] && [ \"\$(stat -c %a /run/stallo/vnc/box)\" = 750 ]"
	check "group member gets the RFB greeting" as labuser python3 -c "$rfb" "$vnc"
	eacces="import socket,sys
try: socket.socket(socket.AF_UNIX).connect(sys.argv[1])
except PermissionError: print('EACCES')"
	check "non-member cannot connect (EACCES)" sh -c "runuser -u outsider -- python3 -c \"$eacces\" $vnc | grep -qx EACCES"
	pid=$(qemu_pid box)
	check "QEMU argv: -vnc unix: only" sh -c "tr '\0' ' ' </proc/$pid/cmdline | grep -q -- '-vnc unix:$vnc ' && ! tr '\0' ' ' </proc/$pid/cmdline | grep -qE 'tcp:|host=|:59[0-9][0-9]'"
	check "ss sees QEMU's sockets (control)" sh -c "ss -H -xlp | grep -q 'pid=$pid,'"
	check "QEMU has no TCP/UDP socket" sh -c "! ss -H -tuanp | grep -q 'pid=$pid,'"
	refused "agents cannot turn VNC on" "only available to humans" sh -c "r=\$(printf '%s\n' '{\"via\":\"mcp\",\"request\":{\"op\":\"set_vnc\",\"name\":\"box\",\"on\":true}}' | python3 -c 'import socket,sys; s=socket.socket(socket.AF_UNIX); s.connect(\"/run/stallo/api.sock\"); s.sendall(sys.stdin.buffer.read()); print(s.recv(4096).decode())'); echo \"\$r\"; echo \"\$r\" | grep -q '\"ok\":true' && exit 0 || exit 1"
	stallo stop box >/dev/null
	check "stop removes the VNC dir" sh -c '[ ! -e /run/stallo/vnc/box ]'
	stallo set box --vnc off >/dev/null
	stallo start box >/dev/null
	check "VNC off: no -vnc, no socket" sh -c "! tr '\0' ' ' </proc/$(qemu_pid box)/cmdline | grep -q -- -vnc && [ ! -e $vnc ]"
	check "stop and remove" sh -c 'stallo stop box && stallo rm --yes box'
}

lifecycle() {
	echo "== service lifecycle"
	stallo new box --cpus 1 --mem 1G --disk 5G >/dev/null
	since=$(date '+%Y-%m-%d %H:%M:%S')
	t0=$(date +%s%N)
	systemctl stop stallod
	echo "stop with one running VM: $(( ($(date +%s%N) - t0) / 1000000 )) ms"
	# KillMode=mixed: the daemon powers the guest off; systemd must not
	# have signalled QEMU itself.
	check "stop powers the guest off (QEMU got no signal)" sh -c '! grep -q "terminating on signal" /var/lib/stallo/vms/box/qemu.log'
	check "stop: no forced power-off" sh -c "! journalctl -u stallod --no-pager --since '$since' | grep -q 'no power-off'"
	check "stop leaves no stallo process" sh -c '! pgrep -u stallo'
	check "stop removes the API socket" sh -c '[ ! -e /run/stallo/api.sock ]'
	systemctl start stallod && wait_sock
	check "start: box is stopped, not lost" sh -c 'stallo ls | grep -q "^box .*stopped"'
	stallo start box >/dev/null
	DEBIAN_FRONTEND=noninteractive apt-get install -y --reinstall "$DEB" >/dev/null
	wait_sock || true
	check "upgrade: daemon back, VMs stopped" sh -c 'systemctl is-active -q stallod && stallo ls | grep -q "^box .*stopped"'
	check "upgrade: table still loaded" nft list table inet stallo
	DEBIAN_FRONTEND=noninteractive apt-get remove -y stallo >/dev/null
	check "remove: no stallo process" sh -c '! pgrep -u stallo'
	check "remove: table deleted" sh -c '! nft list table inet stallo'
	check "remove: VM data and user kept" sh -c 'id stallo && [ -f /var/lib/stallo/vms/box/vm.toml ]'
	DEBIAN_FRONTEND=noninteractive apt-get install -y "$DEB" >/dev/null
	wait_sock || true
	check "reinstall: daemon, table and VM back" sh -c 'systemctl is-active -q stallod && nft list table inet stallo && stallo ls | grep -q "^box"'
	check "remove box" stallo rm --yes box
}

mcp_http() {
	echo "== M5-2: MCP over HTTP (loopback, bearer token)"
	T=/home/labuser/.stallo-token
	runuser -u labuser -- sh -c "umask 077; head -c 32 /dev/urandom | base64 > $T"
	refused "--http 0.0.0.0 refused" "refusing to listen" as labuser stallo mcp --http 0.0.0.0:8765 --token-file $T
	refused "--http on a LAN address refused" "refusing to listen" as labuser stallo mcp --http 192.168.77.1:8765 --token-file $T
	runuser -u labuser -- cp $T $T.open && chmod 644 $T.open
	refused "a world-readable token file refused" "chmod 600" as labuser stallo mcp --http 127.0.0.1:8765 --token-file $T.open
	systemd-run --quiet --unit=mcphttp --uid=labuser --gid=labuser -p SupplementaryGroups=stallo \
		stallo mcp --http 127.0.0.1:8765 --token-file $T
	for _ in $(seq 25); do ss -H -ltn | grep -q 127.0.0.1:8765 && break; sleep 0.2; done
	tok=$(cat $T)
	post() { curl -s -m 30 -H Content-Type:application/json -H Accept:application/json,text/event-stream -H MCP-Protocol-Version:2025-06-18 "$@" http://127.0.0.1:8765/; }
	code() { post -o /dev/null -w '%{http_code}' "$@"; }
	init='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"lab","version":"0"}}}'
	call() { echo "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"$1\",\"arguments\":$2}}"; }
	check "listener is the CLI process on 127.0.0.1 only" sh -c 'ss -H -ltnp | grep ":8765" | grep -q "127.0.0.1:8765.*\"stallo\"" && [ "$(ss -H -ltn | grep -c :8765)" = 1 ]'
	check "S1 still holds: stallod has no IP socket" sh -c '! ss -H -tuanp | grep -q "\"stallod\""'
	auth="Authorization: Bearer $tok"
	r=$(code -d "$init"); check "no token: 401" [ "$r" = 401 ]
	r=$(code -H "Authorization: Bearer x$tok" -d "$init"); check "wrong token: 401" [ "$r" = 401 ]
	r=$(code -H 'Host: evil.example' -H "$auth" -d "$init"); check "foreign Host header: 403" [ "$r" = 403 ]
	r=$(post -H "$auth" -d "$init"); check "initialize with the token" grep -q '"serverInfo"' <<-EOF
		$r
	EOF
	stallo new box --cpus 1 --mem 1G --disk 5G >/dev/null
	r=$(post -H "$auth" -d "$(call exec '{"vm":"box","argv":["true"]}')")
	check "exec refused while agent control is off" sh -c 'echo "$1" | grep -q "agent control is off"' _ "$r"
	stallo agent box on >/dev/null
	r=$(post -H "$auth" -d "$(call exec '{"vm":"box","argv":["echo","via-http"]}')")
	check "exec works with agent control on" sh -c 'echo "$1" | grep -q via-http' _ "$r"
	check "audited as via mcp, peer uid labuser" sh -c "tail -n 1 /var/lib/stallo/audit/box.jsonl | grep -q '\"via\":\"mcp\"' && tail -n 1 /var/lib/stallo/audit/box.jsonl | grep -q '\"uid\":$(id -u labuser)'"
	sleep 1.1
	# 30 requests on one keep-alive connection, faster than the refill.
	urls=$(for _ in $(seq 30); do printf -- '-o /dev/null http://127.0.0.1:8765/ '; done)
	# shellcheck disable=SC2086
	codes=$(curl -s -m 30 -w '%{http_code}\n' -H Content-Type:application/json \
		-H Accept:application/json,text/event-stream -H "$auth" -d "$init" $urls)
	echo "rate limit: $(echo "$codes" | sort | uniq -c | tr '\n' ' ')"
	check "rate limit: 30 requests at once get 429s" sh -c 'echo "$1" | grep -q 429 && [ "$(echo "$1" | grep -c 200)" -le 21 ]' _ "$codes"
	systemctl stop mcphttp
	stallo stop box >/dev/null && stallo rm --yes box >/dev/null
}

case "${1:-all}" in
install) install_pkg; configure ;;
service) service_checks ;;
vm) vm_checks ;;
net)
	BIN=/usr/bin IMAGES=$IMAGES NFT=/etc/stallo/stallo.nft sh "$HERE/m3-network.sh" net
	BIN=/usr/bin IMAGES=$IMAGES NFT=/etc/stallo/stallo.nft sh "$HERE/m3-network.sh" checks || fails=$((fails + 1))
	;;
lifecycle) lifecycle ;;
mcphttp) mcp_http ;;
all)
	install_pkg; configure; service_checks; vm_checks
	BIN=/usr/bin IMAGES=$IMAGES NFT=/etc/stallo/stallo.nft sh "$HERE/m3-network.sh" net
	BIN=/usr/bin IMAGES=$IMAGES NFT=/etc/stallo/stallo.nft sh "$HERE/m3-network.sh" checks || fails=$((fails + 1))
	mcp_http
	lifecycle
	echo "== AppArmor denials for QEMU during the whole gate"
	# The profile's deny rules are `audit deny`, so attempts are logged too.
	# Stacked labels log as stallo-qemu//&unconfined: no closing quote.
	check "no stallo-qemu denials (kernel log, audit log)" sh -c '! { journalctl -k --no-pager; cat /var/log/audit/audit.log 2>/dev/null; } | grep "apparmor=\"DENIED\"" | grep -q "profile=\"stallo-qemu"'
	;;
*) echo "usage: $0 [all|install|service|vm|net|mcphttp|lifecycle]"; exit 2 ;;
esac
echo "failures: $fails"
[ "$fails" = 0 ]
