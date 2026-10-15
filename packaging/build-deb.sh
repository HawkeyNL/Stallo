#!/bin/sh
# Builds target/deb/stallo_<version>_amd64.deb from a release build.
# Needs only cargo and dpkg-deb; no root.
# With --gui it also builds target/deb/stallo-gui_<version>_amd64.deb, which
# needs the GTK 4 and libadwaita dev packages (libgtk-4-dev libadwaita-1-dev
# pkg-config) and binutils.
# $STALLO_DEB_VERSION overrides the version from Cargo.toml (edge builds).
set -eu
cd "$(dirname "$0")/.."
case ${1:-} in
    --gui) gui=true ;;
    '') gui=false ;;
    *) echo "usage: $0 [--gui]" >&2 && exit 2 ;;
esac
version=${STALLO_DEB_VERSION:-$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)}
cargo build --release --locked
rm -rf target/deb/root
root=target/deb/root
install -D -m 755 target/release/stallo "$root/usr/bin/stallo"
install -D -m 755 target/release/stallod "$root/usr/bin/stallod"
install -D -m 644 packaging/stallod.service "$root/usr/lib/systemd/system/stallod.service"
install -D -m 644 packaging/stallo-nft.service "$root/usr/lib/systemd/system/stallo-nft.service"
install -D -m 644 packaging/stallo.nft "$root/etc/stallo/stallo.nft"
install -D -m 644 packaging/apparmor/stallo-qemu "$root/etc/apparmor.d/stallo-qemu"
install -D -m 644 LICENSE "$root/usr/share/doc/stallo/copyright"
install -d "$root/DEBIAN"
install -m 755 packaging/deb/postinst packaging/deb/prerm packaging/deb/postrm "$root/DEBIAN/"
printf '%s\n' /etc/stallo/stallo.nft /etc/apparmor.d/stallo-qemu >"$root/DEBIAN/conffiles"
cat >"$root/DEBIAN/control" <<CONTROL
Package: stallo
Version: $version
Architecture: amd64
Maintainer: HawkeyNL <HawkeyNL@users.noreply.github.com>
Section: admin
Priority: optional
Depends: libc6, passwd, systemd (>= 257), apparmor (>= 4.0), nftables, passt, qemu-system-x86 (>= 1:10.2), qemu-utils, ovmf, xorriso, curl, gpgv, ubuntu-cloudimage-keyring
Description: Agent-first VM manager (QEMU/KVM)
 stallod runs VMs as the system user stallo with per-VM cgroup limits;
 stallo is its CLI and MCP server. The internet network profile is
 isolated by the nftables table in /etc/stallo/stallo.nft.
CONTROL
dpkg-deb --root-owner-group -Zxz --build "$root" "target/deb/stallo_${version}_amd64.deb"

$gui || exit 0
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
 opens an empty window.
CONTROL
dpkg-deb --root-owner-group -Zxz --build "$root" "target/deb/stallo-gui_${version}_amd64.deb"
