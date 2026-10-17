#!/bin/sh
# Renders the GUI's pages to PNGs on a private, headless broadway display
# against a fake daemon. Never uses your desktop session or a TCP port.
# Usage: packaging/dev/shots.sh <output dir>
set -eu
out=$(realpath -m "${1:?usage: $0 <output dir>}")
repo=$(cd "$(dirname "$0")/../.." && pwd)
target=$(realpath -m "${CARGO_TARGET_DIR:-$repo/target}")
cargo build --quiet --locked --manifest-path "$repo/Cargo.toml" -p stallo-gui --features shots
bin="$target/debug/stallo-gui"

# Socket paths must fit in 108 bytes: all of them are relative to the
# work dir, which also stands in for $HOME and the XDG dirs.
work=$(mktemp -d)
bw=
cleanup() {
    if [ -n "$bw" ]; then
        kill "$bw" 2>/dev/null || true
        wait "$bw" 2>/dev/null || true
        bw=
    fi
    rm -rf -- "$work"
}
trap cleanup EXIT
trap 'exit 130' INT HUP
trap 'exit 143' TERM
cd "$work"
mkdir -m 700 rt home cache config data state
unset DISPLAY WAYLAND_DISPLAY DBUS_SESSION_BUS_ADDRESS
export XDG_RUNTIME_DIR=rt HOME="$work/home" XDG_CACHE_HOME="$work/cache" \
    XDG_CONFIG_HOME="$work/config" XDG_DATA_HOME="$work/data" \
    XDG_STATE_HOME="$work/state" STALLO_SHOTS_DIR="$work"
# --unixsocket keeps broadwayd's web viewer off TCP. Display :N listens
# for apps on $XDG_RUNTIME_DIR/broadway<N+1>.socket.
gtk4-broadwayd --unixsocket broadway.sock :41 >broadwayd.log 2>&1 &
bw=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -S rt/broadway42.socket ] && break
    sleep 0.2
done
if [ ! -S rt/broadway42.socket ]; then
    echo "gtk4-broadwayd did not start:" >&2
    cat broadwayd.log >&2
    exit 1
fi
# No a11y bus and no dconf: there is no session bus.
GDK_BACKEND=broadway BROADWAY_DISPLAY=:41 GTK_A11Y=none GSETTINGS_BACKEND=memory \
    timeout 120 "$bin" --screenshot "$out"
