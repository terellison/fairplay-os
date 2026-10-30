#!/usr/bin/env bash
# Install Perforce's p4 (client) and p4d (server) for milestone 2's test.
# Used by provision-guest.sh and CI.  ./vm/install-p4.sh [prefix]
#
# Official builds for this CPU (arm64 or x86_64). Perforce replaces patch
# builds in place within a release, so instead of pinning file hashes this
# checks the published SHA256SUMS and the GPG signature against Perforce's
# package-signing key, whose fingerprint is pinned here.
set -euo pipefail

PREFIX="${1:-/usr/local/bin}"
P4_REL="${P4_REL:-r25.2}"
P4_KEY_FPR="E58131C0AEA7B082C6DC4C937123CB760FF18869"
case "$(uname -m)" in
  aarch64) PLAT=linux26aarch64 ;;
  x86_64)  PLAT=linux26x86_64 ;;
  *) echo "install-p4: no Perforce build for $(uname -m)" >&2; exit 1 ;;
esac

dl="$(mktemp -d)"
trap 'rm -rf "$dl"' EXIT
base="https://cdist2.perforce.com/perforce/$P4_REL/bin.$PLAT"
get() { curl -fsSL --retry 3 --retry-all-errors -o "$dl/$1" "$2"; }
get SHA256SUMS "$base/SHA256SUMS"
get perforce.pubkey https://package.perforce.com/perforce.pubkey

export GNUPGHOME="$dl/gnupg"
mkdir -m700 "$GNUPGHOME"
gpg -q --import "$dl/perforce.pubkey" 2>/dev/null

# Nothing is installed unless it matches SHA256SUMS *and* carries a valid
# signature from the pinned key. A mismatch is reported in full and the file
# fetched again (a damaged download has been seen in CI); three strikes and
# we stop.
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
echo "install-p4: $("$PREFIX/p4" -V | tail -1)"
