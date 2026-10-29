# Source discovery — kunzite_global

Checkpoint: v0.2.0. This is a device identification and provenance checkpoint, **not** a buildable kernel.

## Verified from the device

- Model: `25098RA98G`; codename: `kunzite`; board: `parrot`.
- ROM: HyperOS `OS3.0.304.0.WPQMIXM`; Android 16; Global variant.
- Kernel: `6.6.118-android15-8-ge56cf6b09cca-ab15511674-4k`; arm64; 4 KiB page-size marker.
- The `8` in `android15-8` is the GKI KMI generation, **not** the Android version.

## Reference sources (not confirmed compatible with this device)

- Android common kernel overview: https://source.android.com/docs/core/architecture/kernel/android-common
- Android common kernel repository: https://android.googlesource.com/kernel/common
- Android kernel architecture: https://source.android.com/docs/core/architecture/kernel

A generic `android15-6.6` checkout is **not** automatically compatible with vendor modules or device boot images. Do not select a source revision from Linux version matching alone.

## Acceptance criteria before importing source

1. Establish exact source origin, commit/release, license and attribution.
2. Confirm KMI generation and symbol compatibility with shipped vendor modules.
3. Identify OEM-specific build config, defconfig, device trees and modules.
4. Confirm boot/vendor_boot/init_boot partition layout and recovery plan.
5. Establish a reproducible stock-equivalent build and verify required artifacts.
6. Verify boot and peripherals on a recoverable test device before any tuning.

## CoreFlow interoperability

Umbrella must remain operational without CoreFlow. CoreFlow must discover supported interfaces at runtime. Prefer stable Android/Linux mechanisms, and version any necessary new ABI.
