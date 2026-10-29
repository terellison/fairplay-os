#!/usr/bin/env bash
# Milestone 1 exit check. Run inside the VM after provisioning and a reboot.
set -uo pipefail

pass=0; fail=0
check() {
  local name="$1"; shift
  if "$@" >/dev/null 2>&1; then echo "PASS  $name"; pass=$((pass+1));
  else echo "FAIL  $name"; fail=$((fail+1)); fi
}

# shellcheck disable=SC2016  # these run in a child bash on purpose
check "kernel is 6.x or newer"     bash -c '[ "$(uname -r | cut -d. -f1)" -ge 6 ]'
check "BPF LSM active"             grep -qw bpf /sys/kernel/security/lsm
check "kernel BTF available"       test -r /sys/kernel/btf/vmlinux
check "TPM 2.0 device present"     test -e /dev/tpmrm0
check "TPM answers PCR read"       sudo tpm2_pcrread sha256:0,4,7,10
check "IMA measuring"              sudo test -s /sys/kernel/security/ima/ascii_runtime_measurements
check "btrfs workspace mounted"    bash -c 'findmnt -n -o FSTYPE /work | grep -q btrfs'
check "workspace is a subvolume"   sudo btrfs subvolume show /work/ws
check "nightly + rust-src"         bash -c 'rustup component list --toolchain nightly --installed | grep -q rust-src'
check "bpf-linker installed"       command -v bpf-linker
check "aya-tool installed"         command -v aya-tool

echo "Secure Boot: $(sudo mokutil --sb-state 2>/dev/null || echo 'not available (expected on arm64 QEMU; see README)')"
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
