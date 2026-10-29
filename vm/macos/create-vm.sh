#!/usr/bin/env bash
# Create the milestone-1 VM on an Apple Silicon Mac: arm64 Ubuntu, QEMU with
# Apple's Hypervisor.framework, UEFI firmware, a software TPM 2.0 (swtpm),
# and a second disk for the btrfs workspace. Run once; then use run-vm.sh.
#
#   ./vm/macos/create-vm.sh
#
# Override defaults with env vars, e.g. UBUNTU=resolute DISK_GB=80 ./create-vm.sh
set -euo pipefail

UBUNTU="${UBUNTU:-noble}"          # 24.04 LTS; any release with a 6.x kernel works
DISK_GB="${DISK_GB:-60}"           # root disk
WORK_GB="${WORK_GB:-100}"          # btrfs workspace disk (thin, grows as used)
VM_USER="${VM_USER:-$(whoami)}"
DIR="${VM_DIR:-$HOME/fairplay-vm}"

command -v brew >/dev/null || { echo "Install Homebrew first: https://brew.sh" >&2; exit 1; }
for pkg in qemu swtpm; do
  brew list "$pkg" >/dev/null 2>&1 || brew install "$pkg"
done

QEMU_SHARE="$(brew --prefix qemu)/share/qemu"
mkdir -p "$DIR/tpm" "$DIR/seed"
cd "$DIR"

# UEFI firmware: code is read-only, vars are per-VM and writable.
[ -f efi-code.fd ] || cp "$QEMU_SHARE/edk2-aarch64-code.fd" efi-code.fd
[ -f efi-vars.fd ] || dd if=/dev/zero of=efi-vars.fd bs=1m count=64 2>/dev/null

# Root disk from the Ubuntu cloud image.
IMG="$UBUNTU-server-cloudimg-arm64.img"
if [ ! -f "$IMG" ]; then
  curl -fL -o "$IMG" "https://cloud-images.ubuntu.com/$UBUNTU/current/$IMG"
fi
if [ ! -f root.qcow2 ]; then
  qemu-img create -f qcow2 -F qcow2 -b "$IMG" root.qcow2 "${DISK_GB}G"
fi
[ -f work.qcow2 ] || qemu-img create -f qcow2 work.qcow2 "${WORK_GB}G"

# cloud-init: your user, your SSH key, no password login.
KEY=""
for k in "$HOME/.ssh/id_ed25519.pub" "$HOME/.ssh/id_rsa.pub"; do
  [ -f "$k" ] && { KEY="$(cat "$k")"; break; }
done
if [ -z "$KEY" ]; then
  ssh-keygen -t ed25519 -N "" -f "$HOME/.ssh/id_ed25519"
  KEY="$(cat "$HOME/.ssh/id_ed25519.pub")"
fi

cat > seed/meta-data <<EOF
instance-id: fairplay-vm
local-hostname: fairplay-vm
EOF
cat > seed/user-data <<EOF
#cloud-config
users:
  - name: $VM_USER
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - $KEY
ssh_pwauth: false
package_update: true
packages: [git, curl]
EOF
rm -f seed.iso
hdiutil makehybrid -iso -joliet -default-volume-name cidata -o seed.iso seed >/dev/null

echo "VM created in $DIR."
echo "Next: ./vm/macos/run-vm.sh, then: ssh -p 2222 $VM_USER@localhost"
