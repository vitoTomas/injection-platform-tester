# QEMU testing environment setup guide

Short guide for setting up an eBPF testing environment.

## Distro/Linux configuration x86/64

For testing purposes, Poky (Yocto) reference distribution is recommended.
User-space requires core-image-full-cmdline target with the following addition:

core-image-full-cmdline.bb:
---
`CORE_IMAGE_EXTRA_INSTALL:append = " packagegroup-core-buildessential \
    elfutils elfutils-dev kernel-devsrc tar gzip clang clang-dev \
    clang-libllvm llvm-linker-tools kernel-vmlinux"`

linux-yocto.bb:
---
`KERNEL_DEBUG = "True"`

Kernel debug variable needs to be set so pahole-native can be used during
kernel compile time.

defconfs:
---
Linux defconfigs are provided in the config.gz file in this repository.

Build supported for qemux86_64 machine only (for now)!

## Prepare resources

Place bzImage and rootfs.ext4 files in the resources directory.

## Invoking QEMU

Invoke QEMU VM with the following:
---
```bash
sudo ./run-qemu.sh
```

## After loading QEMU

Run the following after Linux boots:
---

```bash
mkdir -p /mnt/host
mount -t 9p -o trans=virtio hostshare /mnt/host
```
Enables the repository to be accessed by the testing environment in QEMU using
Plan 9 FS Virtio.
