#!/usr/bin/env bash
# Run INSIDE the VM, once, as your normal user:  ./vm/provision-guest.sh
# Installs the toolchain, turns on BPF LSM, formats the btrfs workspace disk,
# and enables IMA. Reboot afterwards, then run vm/check-milestone1.sh.
set -euo pipefail

WORK_DISK="${WORK_DISK:-/dev/vdb}"
WORK_MNT="${WORK_MNT:-/work}"
KVER="$(uname -r)"

echo "== packages"
sudo apt-get update
sudo apt-get install -y \
  build-essential pkg-config clang libclang-dev llvm lld libelf-dev zlib1g-dev \
  "linux-tools-$KVER" linux-tools-common \
  btrfs-progs tpm2-tools libtss2-dev git curl

echo "== kernel config"
for opt in CONFIG_BPF_LSM CONFIG_DEBUG_INFO_BTF CONFIG_BPF_SYSCALL CONFIG_IMA CONFIG_TCG_TPM; do
  if grep -q "^$opt=y" "/boot/config-$KVER"; then echo "  $opt=y"; else echo "  MISSING: $opt" >&2; exit 1; fi
done

echo "== boot parameters: add bpf to the LSM list, enable IMA measurement"
CURRENT_LSM="$(cat /sys/kernel/security/lsm)"
case ",$CURRENT_LSM," in
  *,bpf,*) WANT_LSM="$CURRENT_LSM" ;;
  *) WANT_LSM="$CURRENT_LSM,bpf" ;;
esac
# Ubuntu cloud images set the kernel cmdline in a grub drop-in.
DROPIN=/etc/default/grub.d/90-fairplay.cfg
echo "GRUB_CMDLINE_LINUX_DEFAULT=\"\$GRUB_CMDLINE_LINUX_DEFAULT lsm=$WANT_LSM ima_policy=tcb\"" | sudo tee "$DROPIN" >/dev/null
sudo update-grub

echo "== btrfs workspace on $WORK_DISK"
if ! sudo blkid "$WORK_DISK" >/dev/null 2>&1; then
  sudo mkfs.btrfs -L work "$WORK_DISK"
fi
sudo mkdir -p "$WORK_MNT"
grep -q "LABEL=work" /etc/fstab || echo "LABEL=work $WORK_MNT btrfs defaults,noatime,compress=zstd:1 0 0" | sudo tee -a /etc/fstab >/dev/null
sudo mount -a
[ -d "$WORK_MNT/ws" ] || sudo btrfs subvolume create "$WORK_MNT/ws"
sudo mkdir -p "$WORK_MNT/.snapshots"
sudo chown -R "$USER": "$WORK_MNT"

echo "== Rust (stable for user space, nightly + rust-src for the eBPF program)"
if ! command -v rustup >/dev/null; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  # shellcheck disable=SC1091
  . "$HOME/.cargo/env"
fi
rustup toolchain install nightly --component rust-src
# bpf-linker from source needs a matching LLVM dev install; use the prebuilt
# release binary instead (the upstream-recommended route).
command -v cargo-binstall >/dev/null || cargo install --locked cargo-binstall
command -v bpf-linker >/dev/null || cargo binstall -y bpf-linker
command -v aya-tool >/dev/null || cargo install --git https://github.com/aya-rs/aya aya-tool

echo
echo "Done. Reboot (sudo reboot), then run vm/check-milestone1.sh."
