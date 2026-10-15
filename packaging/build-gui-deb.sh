#!/bin/sh
# Builds target/deb/stallo-gui_<version>_amd64.deb from a release build of
# the desktop app only (packaging/build-deb.sh builds stallo). Needs cargo,
# dpkg-deb, binutils and the GTK 4 and libadwaita dev packages
# (libgtk-4-dev libadwaita-1-dev pkg-config); no root.
# $STALLO_DEB_VERSION overrides the version from Cargo.toml (edge builds).
set -eu
cd "$(dirname "$0")/.."
version=${STALLO_DEB_VERSION:-$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)}
cargo build --release --locked -p stallo-gui
rm -rf target/deb/gui-root
root=target/deb/gui-root
id=io.github.hawkeynl.Stallo
install -D -m 755 -s target/release/stallo-gui "$root/usr/bin/stallo-gui"
install -D -m 644 "packaging/gui/$id.desktop" "$root/usr/share/applications/$id.desktop"
install -D -m 644 "packaging/gui/$id.svg" "$root/usr/share/icons/hicolor/scalable/apps/$id.svg"
install -D -m 644 "packaging/gui/$id-symbolic.svg" "$root/usr/share/icons/hicolor/symbolic/apps/$id-symbolic.svg"
install -D -m 644 "packaging/gui/$id.metainfo.xml" "$root/usr/share/metainfo/$id.metainfo.xml"
install -D -m 644 LICENSE "$root/usr/share/doc/stallo-gui/copyright"

size=$(stat -c %s "$root/usr/bin/stallo-gui")
echo "stallo-gui: $size bytes stripped (budget 15000000)"
[ "$size" -le 15000000 ] || { echo "stallo-gui is over its 15 MB size budget" >&2 && exit 1; }

depends="stallo (= $version), libgtk-4-1 (>= 4.16), libadwaita-1-0 (>= 1.7), libglib2.0-0t64, libgcc-s1, libc6"
# Every library the binary links must come from a package in Depends;
# dpkg -S finds that package on the build system.
dump=$(objdump -p "$root/usr/bin/stallo-gui")
for lib in $(printf '%s\n' "$dump" | awk '$1 == "NEEDED" { print $2 }'); do
    pkg=$(dpkg -S "/usr/lib/x86_64-linux-gnu/$lib" | head -n 1 | cut -d : -f 1)
    printf '%s\n' "$depends" | tr ',' '\n' | sed 's/^ *//; s/ .*//' | grep -Fqx "$pkg" ||
        { echo "stallo-gui links $lib from $pkg, which is not in Depends" >&2 && exit 1; }
    echo "stallo-gui: $lib from $pkg"
done

install -d "$root/DEBIAN"
cat >"$root/DEBIAN/control" <<CONTROL
Package: stallo-gui
Version: $version
Architecture: amd64
Maintainer: HawkeyNL <HawkeyNL@users.noreply.github.com>
Section: admin
Priority: optional
Depends: $depends
Description: Desktop app for Stallo (preview)
 A GNOME app for the VMs that stallod runs. This early preview only
 connects to stallod and helps set up access to it.
CONTROL
dpkg-deb --root-owner-group -Zxz --build "$root" "target/deb/stallo-gui_${version}_amd64.deb"
