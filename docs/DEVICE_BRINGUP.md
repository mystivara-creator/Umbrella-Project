# Redmi Note 15 5G — Device bring-up

**Unverified until data is collected from the exact target phone.** Do not assume codename, SoC, boot layout, or Linux release from a third-party repository name.

## Identify device and firmware

- [ ] Confirm full model number, region and exact Redmi Note 15 5G SKU.
- [ ] Confirm codename from actual device properties and vendor sources.
- [ ] Record SoC, board/platform and vendor firmware/build fingerprint.
- [ ] Record Android, HyperOS, kernel release, kernel config and security patch level.
- [ ] Identify boot, vendor_boot, init_boot, dtbo, vendor_dlkm/system_dlkm as applicable.
- [ ] Check A/B slots and verified boot/AVB requirements.

## Source matching

- [ ] Identify official vendor kernel source release; record exact URLs and commits.
- [ ] Identify Android common kernel (ACK/GKI) baseline and relevant ABI/KMI requirements.
- [ ] Verify config, toolchain version, device trees, modules, DTB/DTBO handling.
- [ ] Preserve upstream authorship, licensing, notices and patch provenance.
- [ ] Avoid importing arbitrary RYSTX or unrelated-device source as baseline.

## Build and verification

- [ ] Establish deterministic CI, toolchain provenance and build logs.
- [ ] Require expected image/module artifacts (missing artifacts must fail CI).
- [ ] Record hashes for each produced artifact and build metadata.
- [ ] Verify module ABI and vendor interoperability.
- [ ] Prepare known-good images, recovery method and data backup **before** physical tests.
- [ ] Validate boot, radio, Wi-Fi, sensors, display, charging and suspend/resume.
- [ ] Collect stock-equivalent benchmark reference and crash/thermal telemetry.

## Commands to collect non-sensitive device facts

```sh
getprop ro.product.device
getprop ro.product.model
getprop ro.build.fingerprint
getprop ro.build.version.release
uname -a
```

Review outputs before sharing: build fingerprints can contain firmware details. Do not share private identifiers, serial numbers or account information.

## Kernel-only test bring-up

The first hardware candidate should replace only the core kernel while retaining
the working device's vendor modules, device trees, vendor_boot and init_boot.
The 259 rebuilt vendor modules remain research artifacts: they are not an
approved replacement for the stock module set. This deployment scope still
requires checking every stock import provided by the new core kernel.

Build #14 (`11742052bd669f11c16a54495b4cbb53ed61d000`) produced an ARM64
Image and system_dlkm images, but no installable boot.img or vendor_boot.img.
Its stock-module comparison has 42 mismatched imports, 758 imports absent from
the build tables, and four conflicting Bluetooth entries. These counts describe
the combined build tables, not a validated deployment of those modules.
Bluetooth is not declared in the pinned kunzite vendor module list and no
bluetooth.ko is present in the flat vendor artifacts; its eventual installation
source must be established before treating the duplicate table entries as a
runtime conflict.

The supplied running GKI stock configuration has SHA-256
`b4bdfa788a4f501ff39d3ed8a6729d728aa4cea8e9fb651ab816383eb8e805e1`.
The GKI configuration embedded in build #14 differs in just
`CONFIG_DEBUG_INFO_COMPRESSED_NONE` and `CONFIG_DEBUG_INFO_COMPRESSED_ZSTD`.
This is not a stock vendor-module build configuration. Copying it over the
vendor configuration does not establish a fix for the vendor CRC differences.

Before repacking a test boot image, collect the active boot backup and runtime
symbol ownership from the target phone. The original module baseline does not
identify the providers of `coldstart_app_tasks` (used by mi_mempool.ko) and
`ufs_xiaomi_comp` (used by ufs_ffu.ko). Depmod indices and runtime export owners
help distinguish core exports from modules loaded during early boot.

In Termux, from the updated repository:

```sh
su -c "sh '$PWD/tools/collect_test_baseline.sh'"
```

The script creates `umbrella-kunzite-test-baseline-<timestamp>.tar.gz` in
Download. It reads the active boot partition and collects firmware/slot
properties, depmod metadata, module names, symbol owners without addresses,
the running configuration and checksums. It does not write any partition,
change boot slots or settings, or include stock .ko binaries. The boot backup
is the current partition image, which may include existing root modifications.

Use that backup to preserve the actual boot header and ramdisk when preparing
the test image. Validate core symbol CRCs, bootloader state, partition size and
the available recovery route before a hardware test. The current core build
does not integrate KernelSU; preservation of the existing root setup must be
assessed from the boot layout. Host tests and successful compilation do not
authorize a flash.

