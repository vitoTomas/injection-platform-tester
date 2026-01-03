#!/bin/bash
set -e

SHARE_DIR="$(pwd)/.."

sudo qemu-system-x86_64 \
  -kernel resources/bzImage \
  -drive file=resources/rootfs.ext4,format=raw,if=virtio \
  -fsdev local,id=fs1,path="$SHARE_DIR",security_model=none \
  -device virtio-9p-pci,fsdev=fs1,mount_tag=hostshare \
  -append "root=/dev/vda rw console=ttyS0" \
  -m 2G \
  -enable-kvm \
  -nographic
