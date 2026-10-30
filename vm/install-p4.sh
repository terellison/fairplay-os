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
for f in p4 p4.asc p4d p4d.asc SHA256SUMS; do curl -fsSL -o "$dl/$f" "$base/$f"; done
curl -fsSL -o "$dl/perforce.pubkey" https://package.perforce.com/perforce.pubkey

export GNUPGHOME="$dl/gnupg"
mkdir -m700 "$GNUPGHOME"
gpg -q --import "$dl/perforce.pubkey" 2>/dev/null
for f in p4 p4d; do
  want="$(awk -v f="*$f" '$2==f {print $1}' "$dl/SHA256SUMS")"
  [ -n "$want" ] || { echo "install-p4: $f missing from SHA256SUMS" >&2; exit 1; }
  echo "$want  $dl/$f" | sha256sum -c --quiet
  gpg --status-fd 1 --verify "$dl/$f.asc" "$dl/$f" 2>/dev/null | grep -q "VALIDSIG.* $P4_KEY_FPR\$" ||
    { echo "install-p4: bad signature on $f" >&2; exit 1; }
done

if [ -w "$PREFIX" ]; then install -m755 "$dl/p4" "$dl/p4d" "$PREFIX/"
else sudo install -m755 "$dl/p4" "$dl/p4d" "$PREFIX/"; fi
echo "install-p4: $("$PREFIX/p4" -V | tail -1)"
