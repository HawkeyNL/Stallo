#!/bin/sh
# Renders the GUI's pages to PNGs on a private, headless broadway display
# against a fake daemon. Never uses your desktop session or a TCP port.
# Usage: packaging/dev/shots.sh <output dir>
set -eu
out=$(realpath -m "${1:?usage: $0 <output dir>}")
repo=$(cd "$(dirname "$0")/../.." && pwd)
cargo build --quiet --locked --manifest-path "$repo/Cargo.toml" -p stallo-gui --features shots
bin="$repo/target/debug/stallo-gui"

# Socket paths must fit in 108 bytes: all of them are relative to the
# work dir.
work=$(mktemp -d)
bw=
cleanup() {
    if [ -n "$bw" ]; then
        kill "$bw" 2>/dev/null || true
        wait "$bw" 2>/dev/null || true
    fi
    rm -f "$work"/*.sock "$work"/rt/*.socket "$work"/broadwayd.log
    rmdir "$work"/rt "$work" 2>/dev/null || true
}
trap cleanup EXIT INT TERM
cd "$work"
mkdir -m 700 rt
unset DISPLAY WAYLAND_DISPLAY DBUS_SESSION_BUS_ADDRESS
export XDG_RUNTIME_DIR=rt
# --unixsocket keeps broadwayd's web viewer off TCP. Display :N listens
# for apps on $XDG_RUNTIME_DIR/broadway<N+1>.socket.
gtk4-broadwayd --unixsocket broadway.sock :41 >broadwayd.log 2>&1 &
bw=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -S rt/broadway42.socket ] && break
    sleep 0.2
done
# No a11y bus and no dconf: there is no session bus.
GDK_BACKEND=broadway BROADWAY_DISPLAY=:41 GTK_A11Y=none GSETTINGS_BACKEND=memory \
    "$bin" --screenshot "$out"
