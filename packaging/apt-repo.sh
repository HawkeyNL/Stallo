#!/bin/sh
# Adds .deb files (stallo, stallo-gui) to the APT repository in <site> (a
# copy of the gh-pages tree), rebuilds every index and signs them with the
# only secret key in $GNUPGHOME. Only the .deb files in pool/ and the
# previous indexes (as by-hash files) are carried over; everything else is
# rebuilt.
# Needs apt-ftparchive (apt-utils), dpkg-deb, gpg and GNU coreutils/findutils.
# Usage: apt-repo.sh <site> <stable|edge> <deb>...
set -eu
[ $# -ge 3 ] || { echo "usage: $0 <site> <stable|edge> <deb>..." >&2 && exit 2; }
site=$1 channel=$2
shift 2
keep_edge=10
url=https://hawkeynl.github.io/Stallo/
deb_name='stallo(-gui)?_[0-9][0-9A-Za-z.+~-]*_amd64\.deb'

case $channel in stable | edge) ;; *) echo "channel must be stable or edge" >&2 && exit 2 ;; esac
[ "$(gpg --batch --list-secret-keys --with-colons | grep -c '^sec:')" = 1 ] ||
    { echo "GNUPGHOME must hold exactly one secret key" >&2 && exit 1; }
# Replaces each argument with its absolute path (the script changes into
# <site>); "for" walks the arguments as they were when it started.
for deb; do
    deb=$(realpath "$deb")
    basename "$deb" | grep -Eqx "$deb_name" || { echo "unexpected package name: $deb" >&2 && exit 1; }
    # The checks below go by file name, so the name must match the control
    # fields apt-ftparchive indexes.
    [ "$(dpkg-deb -f "$deb" Package)_$(dpkg-deb -f "$deb" Version)_$(dpkg-deb -f "$deb" Architecture).deb" = "$(basename "$deb")" ] ||
        { echo "file name does not match the package's control fields: $deb" >&2 && exit 1; }
    set -- "$@" "$deb"
    shift
done

cd "$site"
mkdir -p pool/stable pool/edge
# pool/ holds only what this script put there; anything else means someone
# else wrote to gh-pages, and signing it would vouch for it.
bad=$(find pool -regextype posix-extended \
    ! \( -type d -regex 'pool(/stable|/edge)?' \) \
    ! \( -type f -regex "pool/(stable|edge)/$deb_name" \))
[ -z "$bad" ] || { printf 'unexpected entries in pool/:\n%s\n' "$bad" >&2 && exit 1; }
for deb; do
    target=pool/$channel/$(basename "$deb")
    # A published version never changes: clients cached its checksum.
    [ ! -e "$target" ] || { echo "$target is already published" >&2 && exit 1; }
    cp "$deb" "$target"
done
# Edge file names carry ~git<UTC timestamp>, so the part after "~" sorts by
# age; the names were checked above and hold no whitespace. Each package
# keeps its own last $keep_edge builds.
for pkg in stallo stallo-gui; do
    find pool/edge -name "${pkg}_*.deb" | sort -t '~' -k 2 | head -n "-$keep_edge" | xargs -r rm --
done

# The Pages CDN caches files for minutes, so a client can get the new
# InRelease with an old Packages or the other way round. By-hash indexes
# avoid that; the previous ones stay so a cached InRelease still works.
# ponytail: one previous generation; keep more if publishes come faster
# than the CDN cache expires.
old=$(mktemp -d)
for dist in stable edge; do
    mkdir "$old/$dist"
    # find does not follow symlinks, so nothing outside the tree is copied.
    [ ! -d dists ] || find dists -type f -path "dists/$dist/main/binary-amd64/Packages*" \
        -exec cp {} "$old/$dist/" \;
done
find . -mindepth 1 -maxdepth 1 ! -name pool -exec rm -rf {} +
for dist in stable edge; do
    dir=dists/$dist/main/binary-amd64
    mkdir -p "$dir/by-hash/SHA256" "$dir/by-hash/SHA512"
    for f in "$old/$dist"/*; do
        [ -f "$f" ] || continue
        cp "$f" "$dir/by-hash/SHA256/$(sha256sum <"$f" | cut -d ' ' -f 1)"
        cp "$f" "$dir/by-hash/SHA512/$(sha512sum <"$f" | cut -d ' ' -f 1)"
    done
    apt-ftparchive packages "pool/$dist" >"$dir/Packages"
    gzip -9nk "$dir/Packages"
    apt-ftparchive \
        -o APT::FTPArchive::DoByHash=true \
        -o APT::FTPArchive::Release::Acquire-By-Hash=yes \
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
rm -rf "$old"
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
sudo tee /etc/apt/sources.list.d/stallo.sources &gt;/dev/null &lt;&lt;'EOF'
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
