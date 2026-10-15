#!/bin/sh
# Adds a .deb to the APT repository in <site>, rebuilds every index and signs
# them with the only secret key in $GNUPGHOME. Only pool/ is carried over
# from the old tree; dists/, stallo.asc and index.html are always rebuilt.
# Needs apt-ftparchive (apt-utils), gpg and GNU coreutils.
# Usage: apt-repo.sh <site> <stable|edge> <deb>
set -eu
site=$1 channel=$2 deb=$3
keep_edge=10
url=https://hawkeynl.github.io/Stallo/

case $channel in stable | edge) ;; *) echo "channel must be stable or edge" >&2 && exit 2 ;; esac
[ "$(gpg --batch --list-secret-keys --with-colons | grep -c '^sec:')" = 1 ] ||
    { echo "GNUPGHOME must hold exactly one secret key" >&2 && exit 1; }

mkdir -p "$site/pool/stable" "$site/pool/edge"
target=$site/pool/$channel/$(basename "$deb")
# A published version never changes: clients cached its checksum.
[ ! -e "$target" ] || { echo "$target is already published" >&2 && exit 1; }
cp "$deb" "$target"
# Edge versions carry ~git<yyyymmddHHMM>, so the part after "~" sorts by age.
ls "$site"/pool/edge/*.deb 2>/dev/null | sort -t '~' -k 2 | head -n "-$keep_edge" | xargs -r rm --

cd "$site"
find . -mindepth 1 -maxdepth 1 ! -name pool -exec rm -rf {} +
for dist in stable edge; do
    dir=dists/$dist/main/binary-amd64
    mkdir -p "$dir"
    apt-ftparchive packages "pool/$dist" >"$dir/Packages"
    gzip -9nk "$dir/Packages"
    apt-ftparchive \
        -o APT::FTPArchive::Release::Origin=Stallo \
        -o APT::FTPArchive::Release::Label=Stallo \
        -o "APT::FTPArchive::Release::Suite=$dist" \
        -o "APT::FTPArchive::Release::Codename=$dist" \
        -o APT::FTPArchive::Release::Architectures=amd64 \
        -o APT::FTPArchive::Release::Components=main \
        release "dists/$dist" >Release.tmp
    mv Release.tmp "dists/$dist/Release"
    gpg --batch --yes --digest-algo SHA512 --clearsign -o "dists/$dist/InRelease" "dists/$dist/Release"
    gpg --batch --yes --digest-algo SHA512 --detach-sign --armor -o "dists/$dist/Release.gpg" "dists/$dist/Release"
done
gpg --batch --armor --export >stallo.asc
: >.nojekyll
cat >index.html <<HTML
<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Stallo APT repository</title>
<h1>Stallo APT repository</h1>
<p>Ubuntu 26.04, amd64. Channels: <code>stable</code> (releases) and
<code>edge</code> (every change to main). Check the key's fingerprint
against the one the owner published before you trust it.</p>
<pre>
sudo install -d -m 0755 /etc/apt/keyrings
sudo curl -fsSLo /etc/apt/keyrings/stallo.asc ${url}stallo.asc
gpg --show-keys /etc/apt/keyrings/stallo.asc
sudo tee /etc/apt/sources.list.d/stallo.sources &lt;&lt;EOF
Types: deb
URIs: ${url}
Suites: stable
Components: main
Architectures: amd64
Signed-By: /etc/apt/keyrings/stallo.asc
EOF
sudo apt update &amp;&amp; sudo apt install stallo
</pre>
<p>Use <code>Suites: edge</code> for the edge channel. More:
<a href="https://github.com/HawkeyNL/Stallo/blob/main/docs/apt-repo.md">docs/apt-repo.md</a>.</p>
</html>
HTML
