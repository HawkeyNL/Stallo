#!/bin/sh
# M3 gate for the `internet` profile (S14, S15, port forward, RAM snapshot).
#
# LAB VM ONLY. It needs root, rewires networking and loads nftables rules,
# so it refuses to run unless /etc/stallo-lab exists. Never run it on a real
# host. See docs/network-verification.md for the lab layout.
#
# Needs in the lab VM: passt, nftables, qemu-system-x86, qemu-utils, ovmf,
# xorriso, python3, curl, and
#   $BIN     directory with the stallo and stallod binaries
#   $IMAGES  directory with ubuntu-26.04.qcow2 and debs/26.04/*.deb
#   $NFT     the table (default: packaging/stallo.nft next to this script)
#
# Prints PASS/FAIL per check and exits non-zero on any failure.
set -eu
[ "$(id -u)" = 0 ] || { echo "run as root (inside the lab VM)"; exit 2; }
[ -e /etc/stallo-lab ] || { echo "refusing: /etc/stallo-lab is missing; this is not a lab VM"; exit 2; }
: "${BIN:?}" "${IMAGES:?}"
NFT=${NFT:-$(dirname "$0")/../../packaging/stallo.nft}
SOCK=/run/stallo/api.sock
S() { "$BIN/stallo" --socket "$SOCK" "$@"; }
fails=0
pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; fails=$((fails + 1)); }
check() { name=$1; shift; if "$@" >/dev/null 2>&1; then pass "$name"; else fail "$name"; fi; }
# refused NAME TEXT CMD...: CMD must fail with TEXT in its message.
refused() {
	name=$1 want=$2; shift 2
	if out=$("$@" 2>&1); then fail "$name (succeeded)"
	elif echo "$out" | grep -q "$want"; then pass "$name"
	else fail "$name ($out)"; fi
}

# --- Simulated networks -----------------------------------------------------
# netns inet = the internet (198.51.100.1, 2001:db8:1::1; router .254)
# netns lan  = deny targets that are not this host's addresses
# root ns    = this host: 127.0.0.1, 192.168.77.1, 169.254.9.1, and the
#              host-only aliases 203.0.113.7 and 2001:db8:2::7 (no deny set)
setup_net() {
	ip netns add inet && ip netns add lan
	ip link add veth-inet type veth peer name eth0 netns inet
	ip link add veth-lan type veth peer name eth0 netns lan
	ip addr add 198.51.100.2/24 dev veth-inet
	ip -6 addr add 2001:db8:1::2/64 dev veth-inet nodad
	ip addr add 192.168.77.1/24 dev veth-lan
	ip addr add 169.254.9.1/16 dev veth-lan
	ip -6 addr add fd00:77::1/64 dev veth-lan nodad
	ip addr add 203.0.113.7/32 dev lo
	ip -6 addr add 2001:db8:2::7/128 dev lo
	ip link set veth-inet up && ip link set veth-lan up
	ip -n inet addr add 198.51.100.1/24 dev eth0
	ip -n inet addr add 198.51.100.254/24 dev eth0
	ip -n inet -6 addr add 2001:db8:1::1/64 dev eth0 nodad
	ip -n lan addr add 192.168.77.2/24 dev eth0
	for a in 10.1.2.3/32 172.16.5.5/32 100.100.100.100/32 169.254.9.9/16; do
		ip -n lan addr add "$a" dev eth0
	done
	ip -n lan -6 addr add fd00:77::2/64 dev eth0 nodad
	for n in inet lan; do ip -n $n link set lo up; ip -n $n link set eth0 up; done
	ip route add default via 198.51.100.254
	ip -6 route add default via 2001:db8:1::1
	for r in 10.0.0.0/8 172.16.0.0/12 100.64.0.0/10; do ip route add $r via 192.168.77.2; done
	ip -n lan route add default via 192.168.77.1
	ip -n lan -6 route add default via fd00:77::1
	sysctl -qw net.ipv4.ip_forward=0
	for n in root lan inet; do mkdir -p /srv/$n; echo "hello from $n" >/srv/$n/index.html; done
	cat >/srv/udp.py <<-'EOF'
		import socket, sys
		s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM); s.bind(("::", 9999))
		while True:
		    d, a = s.recvfrom(512); s.sendto(b"echo:" + d, a)
	EOF
	cat >/srv/dns.py <<-'EOF'
		# target.test A 198.51.100.1; everything else NXDOMAIN.
		import socket, struct
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("198.51.100.1", 53))
		while True:
		    q, a = s.recvfrom(512); i = 12
		    while q[i]: i += q[i] + 1
		    hit = q[12:i + 1] == b"\x06target\x04test\x00" and q[i + 1:i + 3] == b"\x00\x01"
		    hdr = q[:2] + struct.pack("!HHHHH", 0x8180 if hit else 0x8183, 1, int(hit), 0, 0)
		    ans = struct.pack("!HHHIH", 0xC00C, 1, 1, 60, 4) + socket.inet_aton("198.51.100.1") if hit else b""
		    s.sendto(hdr + q[12:i + 5] + ans, a)
	EOF
	bg() { setsid "$@" >/dev/null 2>&1 </dev/null & }
	bg python3 -m http.server --bind :: --directory /srv/root 8000
	bg ip netns exec lan python3 -m http.server --bind :: --directory /srv/lan 8000
	bg ip netns exec inet python3 -m http.server --bind :: --directory /srv/inet 80
	bg ip netns exec lan python3 /srv/udp.py
	bg ip netns exec inet python3 /srv/udp.py
	bg ip netns exec inet python3 /srv/dns.py
	sleep 1
}

# --- The daemon, as user stallo, in production mode --------------------------
setup_daemon() {
	id stallo >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin --groups kvm stallo
	install -d -o stallo -g stallo -m 700 /var/lib/stallo /var/lib/stallo/images /var/lib/stallo/images/debs
	install -o stallo -g stallo -m 444 "$IMAGES/ubuntu-26.04.qcow2" /var/lib/stallo/images/
	cp -r "$IMAGES/debs/26.04" /var/lib/stallo/images/debs/ && chown -R stallo:stallo /var/lib/stallo/images/debs
	# A 2-vCPU, 3 GiB lab VM: room for one 1-vCPU, 1 GiB guest.
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
	nft -f "$NFT"
	systemd-run --quiet --unit=stallod --uid=stallo --gid=stallo -p SupplementaryGroups=kvm \
		-p Delegate=yes -p StateDirectory=stallo -p RuntimeDirectory=stallo \
		-E STALLO_LOG=info "$BIN/stallod"
	for _ in $(seq 50); do [ -S $SOCK ] && return; sleep 0.2; done
	echo "stallod did not come up"; journalctl -u stallod --no-pager | tail; exit 1
}

# --- Checks ---------------------------------------------------------------
# One target from the guest; prints REACHED or blocked.
GUEST_PROBE='t() { if [ "$1" = udp ]; then
  r=$(python3 -c "import socket,sys;s=socket.socket(socket.AF_INET6 if \":\" in sys.argv[1] else socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2);s.sendto(b\"x\",(sys.argv[1],9999));print(s.recv(64).decode())" "$2" 2>/dev/null)
elif [ "$1" = ping ]; then ping -c1 -W2 "$2" >/dev/null 2>&1 && r=pong
else r=$(curl -s -m 4 "$2" 2>/dev/null); fi
[ -n "$r" ] && echo REACHED || echo blocked; }; t'

guest() { S exec --timeout 30 web -- sh -c "$GUEST_PROBE \"\$@\"" probe "$@"; }
reach() { r=$(guest "$2" "$3"); [ "$r" = REACHED ] && pass "reaches $1" || fail "reaches $1 ($r)"; }
deny() { r=$(guest "$2" "$3"); [ "$r" = blocked ] && pass "blocks $1" || fail "blocks $1 ($r)"; }

run_checks() {
	echo "== S15: no table, no internet VM"
	nft delete table inet stallo
	refused "new --net internet without the table" "isolation unavailable" \
		S new nope --net internet --cpus 1 --mem 1G --disk 5G
	nft -f "$NFT"

	echo "== create (forward 127.0.0.1:8080 -> 80)"
	t0=$(date +%s)
	S new web --net internet --cpus 1 --mem 1G --disk 5G --forward 8080:80
	echo "ready after $(( $(date +%s) - t0 )) s"
	S ls

	echo "== S14 from the guest"
	reach "internet IPv4"           tcp http://198.51.100.1/
	reach "internet IPv6"           tcp "http://[2001:db8:1::1]/"
	reach "internet by DNS name"    tcp http://target.test/
	reach "internet UDP"            udp 198.51.100.1
	reach "internet ping"           ping 198.51.100.1
	deny "LAN host"                 tcp http://192.168.77.2:8000/
	deny "LAN host UDP"             udp 192.168.77.2
	deny "LAN host ping"            ping 192.168.77.2
	deny "10/8"                     tcp http://10.1.2.3:8000/
	deny "172.16/12"                tcp http://172.16.5.5:8000/
	deny "Tailscale 100.64/10"      tcp http://100.100.100.100:8000/
	deny "link-local"               tcp http://169.254.9.9:8000/
	deny "IPv6 ULA"                 tcp "http://[fd00:77::2]:8000/"
	deny "IPv6 ULA UDP"             udp fd00:77::2
	deny "host LAN address"         tcp http://192.168.77.1:8000/
	deny "host link-local"          tcp http://169.254.9.1:8000/
	deny "host-only IPv4"           tcp http://203.0.113.7:8000/
	deny "host-only IPv6"           tcp "http://[2001:db8:2::7]:8000/"
	deny "gateway, other port"      tcp http://198.51.100.254:8000/

	echo "== port forward"
	S exec --admin web -- sh -c 'mkdir -p /srv/g && echo hello-from-guest >/srv/g/index.html && (setsid python3 -m http.server -d /srv/g 80 >/dev/null 2>&1 </dev/null &)'
	sleep 1
	check "127.0.0.1:8080 reaches guest:80" sh -c 'curl -s -m 4 http://127.0.0.1:8080/ | grep -q hello-from-guest'
	refused "forward is not on 198.51.100.2:8080" "" curl -s -m 2 http://198.51.100.2:8080/

	echo "== RAM snapshot with passt attached"
	check "snap" S snap web s1
	check "restore" S restore web s1
	reach "internet after restore" tcp http://198.51.100.1/
	check "forward after restore" sh -c 'curl -s -m 4 http://127.0.0.1:8080/ | grep -q hello-from-guest'

	echo "== S15: table removed while the VM runs"
	nft delete table inet stallo
	paused=
	for _ in $(seq 10); do
		S ls | grep -q 'paused (isolation lost)' && { paused=1; break; }
		sleep 0.5
	done
	[ -n "$paused" ] && pass "running internet VM paused within 5 s" || fail "running internet VM paused within 5 s"
	refused "resume without the table" "isolation unavailable" S resume web
	nft -f "$NFT"
	check "resume with the table" S resume web
	reach "internet after resume" tcp http://198.51.100.1/

	echo "== cleanup"
	S stop web && S rm --yes web
}

case "${1:-all}" in
net) setup_net ;;
daemon) setup_daemon ;;
checks) run_checks ;;
all) setup_net; setup_daemon; run_checks ;;
*) echo "usage: $0 [all|net|daemon|checks]"; exit 2 ;;
esac
echo "failures: $fails"
[ "$fails" = 0 ]
