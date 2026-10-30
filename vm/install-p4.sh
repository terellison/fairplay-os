#!/usr/bin/env bash
# Install Perforce's p4 (client) and p4d (server) for milestone 2's test.
# Used by provision-guest.sh and CI.  ./vm/install-p4.sh [prefix]
#
# Two sources, both checked against Perforce's package-signing key, whose
# fingerprint is pinned here:
#   apt      Perforce's apt repository. x86_64 Ubuntu only (that's CI). apt
#            verifies the signed repo index and every package's hash.
#   tarball  The release binaries on Perforce's CDN, for everything else (the
#            arm64 VM). Each must match the published SHA256SUMS *and* carry
#            a valid signature. A CDN edge near GitHub's runners has served a
#            stale p4 that fails this, which is why CI uses apt.
# P4_SOURCE=apt|tarball overrides the choice.
set -euo pipefail

PREFIX="${1:-/usr/local/bin}"
P4_REL="${P4_REL:-r25.2}"                  # tarball release directory
P4_DEB_VERSION="${P4_DEB_VERSION:-2025.2-3086021}"  # same build as $P4_REL
P4_KEY_FPR="E58131C0AEA7B082C6DC4C937123CB760FF18869"

dl="$(mktemp -d)"
trap 'rm -rf "$dl"' EXIT
get() { curl -fsSL --retry 3 --retry-all-errors -o "$dl/$1" "$2"; }
as_root() { if [ "$(id -u)" = 0 ]; then "$@"; else sudo "$@"; fi; }
# A field from /etc/os-release, e.g. os_field ID -> ubuntu.
os_field() { sed -n "s/^$1=\"\{0,1\}\([^\"]*\)\"\{0,1\}\$/\1/p" /etc/os-release 2>/dev/null; }

# Perforce's public key, refused unless it is the key we expect.
get perforce.pubkey https://package.perforce.com/perforce.pubkey
export GNUPGHOME="$dl/gnupg"
mkdir -m700 "$GNUPGHOME"
gpg -q --import "$dl/perforce.pubkey" 2>/dev/null
gpg --with-colons --fingerprint | grep -q "^fpr:*$P4_KEY_FPR:" ||
  { echo "install-p4: perforce.pubkey is not key $P4_KEY_FPR" >&2; exit 1; }

source="${P4_SOURCE:-}"
if [ -z "$source" ]; then
  if [ "$(uname -m)" = x86_64 ] && [ "$(os_field ID)" = ubuntu ]; then source=apt; else source=tarball; fi
fi

install_apt() {
  local codename keyring=/etc/apt/keyrings/perforce.gpg list=/etc/apt/sources.list.d/perforce.list
  codename="$(os_field VERSION_CODENAME)"
  gpg --export "$P4_KEY_FPR" > "$dl/perforce.gpg"
  as_root install -D -m644 "$dl/perforce.gpg" "$keyring"
  echo "deb [arch=amd64 signed-by=$keyring] https://package.perforce.com/apt/ubuntu $codename release" |
    as_root tee "$list" >/dev/null
  # Refresh only Perforce's index; the rest of apt's sources are untouched.
  as_root apt-get update -q -o Dir::Etc::sourcelist="$list" -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0
  # Just the binaries: the full p4-server package also creates a service user
  # and data directory, which the test doesn't need.
  local v="$P4_DEB_VERSION~$codename" series="${P4_DEB_VERSION%%-*}"
  as_root apt-get install -y -q --no-install-recommends \
    "p4-cli-base=$v" "p4-server-base-${series#20}=$v"
  as_root ln -sf /opt/perforce/bin/p4 "$PREFIX/p4"
  as_root ln -sf "/opt/perforce/sbin/p4d.${series#20}" "$PREFIX/p4d"
}

install_tarball() {
  local plat f want attempt
  case "$(uname -m)" in
    aarch64) plat=linux26aarch64 ;;
    x86_64)  plat=linux26x86_64 ;;
    *) echo "install-p4: no Perforce build for $(uname -m)" >&2; exit 1 ;;
  esac
  local base="https://cdist2.perforce.com/perforce/$P4_REL/bin.$plat"
  get SHA256SUMS "$base/SHA256SUMS"
  # Nothing is installed unless it matches SHA256SUMS and is signed by the
  # pinned key. A mismatch is reported in full and fetched again; three
  # strikes and we stop.
  verified() {
    local f="$1" want="$2" got
    got="$(sha256sum "$dl/$f" | cut -d' ' -f1)"
    if [ "$got" != "$want" ]; then
      echo "install-p4: $f checksum mismatch: want $want, got $got ($(stat -c %s "$dl/$f") bytes)" >&2
      return 1
    fi
    if ! gpg --status-fd 1 --verify "$dl/$f.asc" "$dl/$f" 2>/dev/null | grep -q "VALIDSIG.* $P4_KEY_FPR\$"; then
      echo "install-p4: $f has no valid signature from $P4_KEY_FPR" >&2
      return 1
    fi
  }
  for f in p4 p4d; do
    want="$(awk -v f="*$f" '$2==f {print $1}' "$dl/SHA256SUMS")"
    [ -n "$want" ] || { echo "install-p4: $f missing from SHA256SUMS" >&2; exit 1; }
    for attempt in 1 2 3; do
      get "$f" "$base/$f" && get "$f.asc" "$base/$f.asc" && verified "$f" "$want" && break
      [ "$attempt" = 3 ] && { echo "install-p4: giving up on $f" >&2; exit 1; }
      echo "install-p4: retrying $f ($attempt/3 failed)" >&2
      sleep 5
    done
  done
  if [ -w "$PREFIX" ]; then install -m755 "$dl/p4" "$dl/p4d" "$PREFIX/"
  else sudo install -m755 "$dl/p4" "$dl/p4d" "$PREFIX/"; fi
}

case "$source" in
  apt) install_apt ;;
  tarball) install_tarball ;;
  *) echo "install-p4: P4_SOURCE must be apt or tarball, not '$source'" >&2; exit 1 ;;
esac
echo "install-p4 ($source): $("$PREFIX/p4" -V | tail -1); $("$PREFIX/p4d" -V | tail -2 | head -1)"
