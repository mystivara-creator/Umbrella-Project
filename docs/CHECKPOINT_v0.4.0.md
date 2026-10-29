# Checkpoint v0.4.0 — Unified Multi-Region Gate

- Introduces a fail-closed region compatibility manifest.
- Records the observed Global firmware as reference only.
- Lists other regions as planned, not supported.
- Adds CI schema checks and negative unit tests.
- Does not import kernel source, build an image, or approve flashing.

Next: verify upstream/vendor kernel provenance and KMI for the observed device.
