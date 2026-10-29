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
