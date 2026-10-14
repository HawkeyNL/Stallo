#!/bin/sh
# Builds target/deb/stallo_<version>_amd64.deb from a release build.
# Needs only cargo and dpkg-deb; no root.
set -eu
cd "$(dirname "$0")/.."
version=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)
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
Depends: libc6, passwd, systemd (>= 257), apparmor, nftables, passt, qemu-system-x86 (>= 1:10.2), qemu-utils, ovmf, xorriso, curl, gpgv, ubuntu-cloudimage-keyring
Description: Agent-first VM manager (QEMU/KVM)
 stallod runs VMs as the system user stallo with per-VM cgroup limits;
 stallo is its CLI and MCP server. The internet network profile is
 isolated by the nftables table in /etc/stallo/stallo.nft.
CONTROL
dpkg-deb --root-owner-group -Zxz --build "$root" "target/deb/stallo_${version}_amd64.deb"
