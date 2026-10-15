# The APT repository

Stallo is published as a signed APT repository on GitHub Pages:
`https://hawkeynl.github.io/Stallo/`. Ubuntu 26.04, amd64 only.

| Channel | Published | Version | Kept |
|---|---|---|---|
| `stable` | on a tag `v<major>.<minor>.<patch>` | the tag; it must equal `version` in `Cargo.toml` | all |
| `edge` | on every push to `main` | `<Cargo.toml version>~git<UTC yyyymmddHHMMSS>.<sha7>` | the last 10 per package |

Each build publishes two packages with the same version: `stallo` (the
daemon and CLI) and `stallo-gui` (the desktop app).

An edge build sorts after every earlier edge build and before the release of
the version in `Cargo.toml`. So `Cargo.toml` holds the **next** version:
bump it right after tagging a release, or edge builds sort below that
release.

## How it is built

`.github/workflows/apt-publish.yml`, on the `ubuntu-26.04` runner:

1. **build:** builds the `stallo` `.deb` with `packaging/build-deb.sh`. This job
   runs the crates' build scripts, so it never gets the signing key.
   - An edge run whose commit is no longer the tip of `main` (a re-run of an
     old run) fails, so an older build can never become the newest one.
   - **build-gui** then builds the `stallo-gui` `.deb` with
     `packaging/build-gui-deb.sh` on its own runner (with the GTK and
     libadwaita dev packages), so the GUI's build scripts never run next to
     the `stallo` package. It takes the version from build and repeats the
     tip-of-`main` check.
2. **repo:** on a fresh runner that checks out only `packaging/apt-repo.sh`,
   takes the `.deb` files in `pool/` from the current `gh-pages` branch,
   adds the new ones, drops edge builds beyond the last 10 of each
   package, and rebuilds and
   signs every index (`apt-ftparchive`). Everything else is rebuilt each
   time: `dists/{stable,edge}` (`Packages`, `Packages.gz`, `Release`,
   `InRelease`, `Release.gpg`, `by-hash/`), `stallo.asc` (the public key),
   `index.html` and `.nojekyll`.
   - The signing key comes from the secret `STALLO_APT_SIGNING_KEY` (and
     `STALLO_APT_SIGNING_PASSPHRASE` if it has one) in the environment
     `apt-signing`, which only `main` and `v*` tags may use. It is imported
     into a throwaway `GNUPGHOME` that the step deletes when it ends.
     **Without the secret the run fails**; it never publishes an unsigned
     repository.
   - `pool/` on `gh-pages` may hold only `stallo_*_amd64.deb` and
     `stallo-gui_*_amd64.deb` files in
     `stable/` and `edge/`; anything else (a symlink, another file) fails
     the run instead of being signed.
   - A stable version that is already published is refused: its checksum
     must never change.
   - The Pages CDN caches files for about 10 minutes, so the indexes are
     also published by hash (`Acquire-By-Hash`), and the previous
     generation stays: a client with a cached `InRelease` still finds the
     matching `Packages`.
3. **verify:** a clean `ubuntu:26.04` container adds the new tree as a
   `file:` source with `Signed-By: stallo.asc`, and runs
   `apt-get update --error-on=any` (signatures) and
   `apt-get install --dry-run stallo=<version> stallo-gui=<version>`
   (dependencies resolve against the Ubuntu archive), then downloads both
   `.deb` files (their checksums against the signed index).
4. **publish:** commits the tree as one orphan commit and force-pushes it to
   `gh-pages` (with a lease on the commit the repo job read), so the branch
   never grows. GitHub Pages serves the branch.

Pull requests run steps 1 to 3 with a throwaway key made in the job, no
environment and no secret, and publish nothing. One publish runs at a time (concurrency group
`apt-publish`).

`gh-pages` is written only by this workflow. Do not push to it by hand: the
next publish keeps only the `.deb` files in `pool/`.

## Owner: one-time setup

Run these on your own machine, not in CI.

1. **Create the signing key** (asks for a passphrase; one is optional):

   ```sh
   export GPG_TTY=$(tty)
   gpg --quick-gen-key "Stallo Archive Signing" ed25519 sign 2y
   gpg --list-keys "Stallo Archive Signing"
   FPR=<the new key's fingerprint, from the line above>
   ```

   - Note the fingerprint: laptops compare against it.
   - gpg wrote a revocation certificate to
     `~/.gnupg/openpgp-revocs.d/$FPR.rev`. Keep it, and a backup of the
     key (`gpg --armor --export-secret-keys "$FPR"`), offline.

2. **Create the environment `apt-signing`**, usable only from `main` and
   `v*` tags (a repository secret would reach a workflow on any branch):

   ```sh
   gh api -X PUT repos/HawkeyNL/Stallo/environments/apt-signing \
     -F 'deployment_branch_policy[protected_branches]=false' \
     -F 'deployment_branch_policy[custom_branch_policies]=true'
   gh api -X POST repos/HawkeyNL/Stallo/environments/apt-signing/deployment-branch-policies -f name=main -f type=branch
   gh api -X POST repos/HawkeyNL/Stallo/environments/apt-signing/deployment-branch-policies -f 'name=v*' -f type=tag
   ```

   Then store the private key as its secret, straight from a pipe, so it
   never lands in a file:

   ```sh
   gpg --armor --export-secret-keys "$FPR" | gh secret set STALLO_APT_SIGNING_KEY --env apt-signing --repo HawkeyNL/Stallo
   ```

   If the key has a passphrase, store it too (`gh` prompts for it, so it
   stays out of the shell history):

   ```sh
   gh secret set STALLO_APT_SIGNING_PASSPHRASE --env apt-signing --repo HawkeyNL/Stallo
   ```

   Optional: a tag ruleset so only you can create `v*` tags (any `v*` tag
   reaches the key).

3. **The public key** needs no step: every publish exports it from the
   secret as `https://hawkeynl.github.io/Stallo/stallo.asc`. To keep a copy:
   `gpg --armor --export "$FPR" > stallo.asc`.

4. **Publish once and enable Pages.** Push to `main` (or re-run the latest
   `APT repository` run on `main`); it creates the `gh-pages` branch. Then
   enable Pages from that branch, in *Settings → Pages* (source: *Deploy
   from a branch*, `gh-pages`, `/ (root)`) or with:

   ```sh
   gh api -X POST repos/HawkeyNL/Stallo/pages -f 'source[branch]=gh-pages' -f 'source[path]=/'
   gh api -X PUT repos/HawkeyNL/Stallo/pages -F https_enforced=true
   ```

   Then check that `https://hawkeynl.github.io/Stallo/stallo.asc` loads. If
   a later publish does not show up there, check the *pages build and
   deployment* run in the Actions tab.

## A laptop

```sh
sudo install -d -m 0755 /etc/apt/keyrings
sudo curl -fsSLo /etc/apt/keyrings/stallo.asc https://hawkeynl.github.io/Stallo/stallo.asc
gpg --show-keys /etc/apt/keyrings/stallo.asc   # the fingerprint must match the owner's
sudo tee /etc/apt/sources.list.d/stallo.sources >/dev/null <<'EOF'
Types: deb
URIs: https://hawkeynl.github.io/Stallo/
Suites: edge
Components: main
Architectures: amd64
Signed-By: /etc/apt/keyrings/stallo.asc
EOF
sudo apt update && sudo apt install stallo
```

- `Suites: stable` for releases only. After each change to `main`,
  `sudo apt update && sudo apt upgrade` installs the newest edge build.
- Edge to stable: apt does not downgrade. If the installed edge build is
  newer than the latest release, it stays until a newer release comes out
  (or `sudo apt install stallo=<version>`).
- What the package does on install, upgrade and removal:
  [production.md](production.md).

## Key rotation, expiry and revocation

- **Expiry** (2 years): before it, extend it
  (`gpg --quick-set-expire "$FPR" 2y`), store the key in the secret again
  (step 2) and publish. Laptops must fetch the new `stallo.asc`: the expiry
  is part of their copy of the public key.
- **Rotation:** create a new key (step 1), replace the secret (step 2) and
  publish. The next publish signs with the new key and serves the new
  `stallo.asc`. Every laptop must fetch it and check the new fingerprint;
  until then `apt update` fails for this source (it fails closed).
- **Revocation** (key lost or leaked):
  1. `gh secret delete STALLO_APT_SIGNING_KEY --env apt-signing --repo HawkeyNL/Stallo`
     (and the passphrase): publishing stops.
  2. On every laptop, `sudo rm /etc/apt/keyrings/stallo.asc`: apt trusts
     only that file for this source, so removing it is what revokes the key
     there. Mark the key revoked in your own keyring with the certificate
     from step 1 (`gpg --import` it after removing the `:` in front of
     `-----BEGIN`).
  3. Delete the `gh-pages` branch: its `pool/` may hold packages planted
     by whoever had the key.
  4. A laptop that already installed a package from that time may run a
     planted one: compare `dpkg -s stallo` with a version you trust, and
     reinstall it from the new repository or reinstall the laptop.
  5. Create a new key and secret, and push to `main` for edge. For each
     release to bring back, delete the tag and push it again
     (`git push origin :refs/tags/vX.Y.Z && git push origin vX.Y.Z`; a
     re-run works only within 30 days). Laptops set up again from
     "A laptop".

## Limits

- `Release` has no `Valid-Until`: a mirror could keep serving an old,
  validly signed index. HTTPS to `github.io` is what prevents that here.
- If several pushes arrive while a publish runs, GitHub keeps only the
  newest one waiting. After tagging a release, check that its run
  published; if it was dropped, re-run it (or push the tag again).
- Two pushes to `main` within seconds make the first run fail (main has
  moved on); the second one publishes.
