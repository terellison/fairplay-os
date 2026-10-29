#!/usr/bin/env bash
# Milestone 2 exit test: assetguard against a real (local, throwaway) Perforce
# server. Run inside the VM from the repo root:  ./vm/test-milestone2.sh
#
# Needs p4 and p4d on PATH (see vm/provision-guest.sh) and a btrfs filesystem
# at $M2_DIR's parent. Builds assetguard, starts p4d on 127.0.0.1:$M2_PORT,
# and deletes everything it made when it exits. Your /work/ws is not touched.
#
# Scenarios (each checked with p4's own view of the client, not assetguard's):
#   1. p4 is killed mid-sync with a file half-written    -> roll back
#   2. a file keeps arriving truncated, repair can't fix -> roll back
#   3. a file arrives truncated once                      -> repaired, sync ok
#   4. the depot gains a case-only collision              -> roll back
# "Rolled back" means: disk matches the old revision AND the server's have
# list does too, so p4 never believes the client has files it doesn't.
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
T="${M2_DIR:-/work/m2-test}"
export P4PORT="127.0.0.1:${M2_PORT:-16661}" P4USER=tester P4CLIENT=player
unset P4CONFIG P4PASSWD
REAL_P4="$(command -v p4)" || { echo "p4 not found; run vm/provision-guest.sh" >&2; exit 2; }
command -v p4d >/dev/null || { echo "p4d not found; run vm/provision-guest.sh" >&2; exit 2; }

pass=0; fail=0
ok()  { echo "PASS  $1"; pass=$((pass+1)); }
bad() { echo "FAIL  $1"; fail=$((fail+1)); }
step() { echo; echo "== $1"; }

cleanup() {
  [ -n "${P4D_PID:-}" ] && kill "$P4D_PID" 2>/dev/null && wait "$P4D_PID" 2>/dev/null
  [ -d "$T" ] || return 0
  # Delete subvolumes under $T deepest-first, then the rest.
  local mnt rel
  mnt="$(findmnt -n -o TARGET -T "$T")"
  rel="${T#"$mnt"/}"
  sudo btrfs subvolume list "$mnt" | awk '{print $NF}' | grep "^$rel/" | sort -r |
    while read -r sv; do sudo btrfs subvolume delete "$mnt/$sv" >/dev/null; done
  sudo rm -rf "$T"
}
trap cleanup EXIT

step "build assetguard"
# M2_ASSETGUARD=/path/to/assetguard tests another build (e.g. an old one, to
# see that this test catches its bugs).
if [ -n "${M2_ASSETGUARD:-}" ]; then
  AG="$M2_ASSETGUARD"
else
  (cd "$REPO" && cargo build --release -q -p assetguard) || exit 2
  AG="$REPO/target/release/assetguard"
fi

step "start p4d on $P4PORT"
cleanup
mkdir -p "$T/p4root" "$T/author" "$T/bin"
p4d -r "$T/p4root" -p "$P4PORT" -L "$T/p4d.log" -J off >/dev/null 2>&1 &
P4D_PID=$!
for _ in $(seq 50); do p4 info >/dev/null 2>&1 && break; sleep 0.1; done
p4 info >/dev/null || { echo "p4d did not start; see $T/p4d.log" >&2; exit 2; }

step "seed the depot: @1, then @2 (edits, an add, a delete)"
(
  set -e
  export P4CLIENT=author
  cd "$T/author"
  p4 client -o | sed "s|^Root:.*|Root: $T/author|" | p4 client -i >/dev/null
  mkdir -p Art/props
  head -c 2000000 /dev/urandom > Art/hero.uasset
  head -c 1000000 /dev/urandom > Art/props/crate.uasset
  head -c 500000  /dev/urandom > Art/props/barrel.uasset
  printf 'int main() { return 0; }\n' > main.cpp
  p4 add -t binary Art/hero.uasset Art/props/*.uasset >/dev/null
  p4 add main.cpp >/dev/null
  p4 submit -d "@1" >/dev/null
  p4 edit Art/hero.uasset Art/props/crate.uasset main.cpp >/dev/null
  head -c 2500000 /dev/urandom > Art/hero.uasset
  head -c 1200000 /dev/urandom > Art/props/crate.uasset
  printf 'int main() { return 1; }\n' > main.cpp
  head -c 300000 /dev/urandom > Art/new.uasset
  p4 add -t binary Art/new.uasset >/dev/null
  p4 delete Art/props/barrel.uasset >/dev/null
  p4 submit -d "@2" >/dev/null
) || { echo "seeding the depot failed" >&2; exit 2; }

step "workspace: btrfs subvolume at $T/ws, synced to @1"
btrfs subvolume create "$T/ws" >/dev/null
p4 client -o | sed "s|^Root:.*|Root: $T/ws|" | p4 client -i >/dev/null
p4 sync -q //...@1
SNAPS="$T/snapshots"

# A p4 stand-in that misbehaves on `sync` according to $FAULT, then defers to
# the real p4 for everything else. assetguard picks it up via ASSETGUARD_P4.
cat > "$T/bin/p4-fault" <<EOF
#!/usr/bin/env bash
# args from assetguard: -ztag <command> [flags] [files]
real="$REAL_P4"
victim="$T/ws/Art/props/crate.uasset"
# p4 leaves synced files read-only; cut the file off and put that back.
cut_off() { chmod u+w "\$victim" && truncate -s 4096 "\$victim" && chmod a-w "\$victim"; }
if [ "\${2:-}" = sync ]; then
  forced=no; [ "\${3:-}" = -f ] && forced=yes
  case "\$FAULT" in
    kill)
      # One file lands, the next is cut off while being written, then p4 dies.
      [ \$forced = no ] && { "\$real" -ztag sync -m 1 >/dev/null; cut_off || exit 99; exit 137; } ;;
    truncate-always)
      "\$real" "\$@"; rc=\$?; cut_off || exit 99; exit \$rc ;;
    truncate-once)
      if [ \$forced = no ]; then "\$real" "\$@"; rc=\$?; cut_off || exit 99; exit \$rc; fi ;;
  esac
fi
exec "\$real" "\$@"
EOF
chmod +x "$T/bin/p4-fault"

# Expected have list at a change: "depot#rev" for every file not deleted there.
# (-ztag records, joined with awk: p4 -F mangles a literal '#'.)
want_have() {
  p4 -ztag files "//...@$1" | awk '$2=="depotFile"{f=$3} $2=="rev"{r=$3} $2=="action" && $3!~/delete/{print f "#" r}' | sort
}
have_now() { p4 -ztag have 2>/dev/null | awk '$2=="depotFile"{f=$3} $2=="haveRev"{print f "#" $3}' | sort; }

# The skeptic's check: ask p4, not assetguard, whether the client is at @N.
check_at() {
  local label="$1" change="$2"
  if diff <(want_have "$change") <(have_now) >/dev/null; then
    ok "$label: server have list is exactly @$change"
  else
    bad "$label: server have list is not @$change"; diff <(want_have "$change") <(have_now) | sed 's/^/      /'
  fi
  # reconcile compares every file's content with its have revision and finds
  # files on disk that p4 doesn't know about.
  local rec
  rec="$(cd "$T/ws" && p4 reconcile -n //... 2>&1)"
  if grep -q "no file(s) to reconcile" <<<"$rec"; then
    ok "$label: every file on disk matches its have revision (p4 reconcile -n)"
  else
    bad "$label: disk differs from have list"; sed 's/^/      /' <<<"$rec"
  fi
}

run_ag() {
  local label="$1" want_exit="$2"; shift 2
  echo "-- assetguard sync ($label)"
  (cd "$T" && "$@" "$AG" sync --workspace "$T/ws" --snapshots "$SNAPS") 2>&1 | sed 's/^/   | /'
  local rc=${PIPESTATUS[0]}
  if [ "$rc" -eq "$want_exit" ]; then ok "$label: assetguard exit $rc"; else bad "$label: assetguard exit $rc, wanted $want_exit"; fi
}

step "1. p4 killed mid-sync, a file half-written"
run_ag "killed mid-sync" 1 env ASSETGUARD_P4="$T/bin/p4-fault" FAULT=kill
check_at "killed mid-sync" 1
ls -d "$T"/ws.failed-* >/dev/null 2>&1 && ok "killed mid-sync: broken workspace kept for inspection" || bad "killed mid-sync: no ws.failed-* kept"

step "2. a file keeps arriving truncated (repair fails too)"
run_ag "persistent truncation" 1 env ASSETGUARD_P4="$T/bin/p4-fault" FAULT=truncate-always
check_at "persistent truncation" 1

step "3. a file arrives truncated once (repair fixes it)"
run_ag "one-off truncation" 0 env ASSETGUARD_P4="$T/bin/p4-fault" FAULT=truncate-once
check_at "one-off truncation" 2

step "4. the depot gains Art/Hero.uasset next to Art/hero.uasset"
(
  export P4CLIENT=author
  cd "$T/author" && head -c 1000 /dev/urandom > Art/Hero.uasset &&
    p4 add -t binary Art/Hero.uasset >/dev/null && p4 submit -d "@3: case collision" >/dev/null
)
run_ag "case collision" 1 env
check_at "case collision" 2

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
