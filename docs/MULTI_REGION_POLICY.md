# Umbrella Unified Kernel — Multi-region compatibility policy

**Checkpoint:** v0.4.0 (manifest and CI only).

One source tree may serve multiple ROM regions, but **one binary is not presumed compatible**.
The current reference firmware is `OS3.0.304.0.WPQMIXM` on model `25098RA98G`,
codename `kunzite`, board `parrot`. It is **not yet verified for custom kernel boot**.

## Status semantics

- `planned`: region is a target, no firmware evidence recorded.
- `reference_only`: firmware facts observed on a device, not kernel compatibility.
- `verified`: source provenance, build, device boot and vendor module compatibility
  have all been independently demonstrated for listed firmware(s).

## Required before declaring support

1. Confirm exact device model, board and firmware package provenance.
2. Confirm kernel KMI and vendor module ABI, including module signatures where applicable.
3. Confirm boot image format, device tree, vendor_boot/init_boot and AVB constraints.
4. Build from pinned, attributed sources with reproducible logs and checksums.
5. Test boot, radio, camera, storage, display, sensors, charging and recovery.
6. Record test evidence per firmware and region; review before changing manifest status.

Do not infer China/Indonesia/Global compatibility from the shared `kunzite`
codename or the common Linux version alone. Do not flash anything from this
checkpoint. A verified entry is a documentation claim, not an automatic
guarantee for untested firmware updates.

CoreFlow integration remains optional and is not part of the boot safety path.
