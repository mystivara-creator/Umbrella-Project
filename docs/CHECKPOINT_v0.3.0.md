# Umbrella Project v0.3.0 — Source Discovery Gate

Device: Redmi Note 15 5G / 25098RA98G / kunzite_global / board parrot.
Firmware: OS3.0.304.0.WPQMIXM, Android 16.
Observed kernel: 6.6.118-android15-8-ge56cf6b09cca-ab15511674-4k.

## Deliverables

- Machine-readable source provenance manifest.
- Fail-closed source metadata audit.
- Host build prerequisite checker.
- GitHub Actions metadata gate.

## Blocking conditions

The device-specific matching kernel source, commit, defconfig, Clang toolchain, vendor modules and KMI compatibility are **not verified**. No kernel build or flashable artifact is provided. Do not use unrelated 6.6 kernel images or bypass vendor compatibility checks.

## Next step

Find the vendor's matching source release and record its URL and immutable commit. Confirm source/config matches firmware and vendor modules before enabling kernel compilation. Keep original license notices and provenance.
