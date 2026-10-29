# Roadmap

## F0 — Foundation (current)

- Independent repository identity and documentation.
- Device manifest with explicit `unverified` status.
- Source provenance and architecture contract.
- CI validating documentation foundation only.

## F1 — Stock-equivalent kernel baseline

- Identify device-specific source and correct upstream version.
- Import source while retaining authorship/license information.
- Build kernel with pinned tools and deterministic configuration.
- Verify required artifacts, vendor modules and boot compatibility.

## F2 — Reliability and observability

- Recovery and rollback procedures for test devices.
- Baseline measurements: frame-time distribution, app launch, PSI, I/O and temperatures.
- Regression gates for boot, suspend, network, charging, and battery use.

## F3 — Measured kernel improvements

- Patch one subsystem at a time against recorded baseline.
- Evaluate improvements across load/thermal states and repeat runs.
- Keep only proven changes with transparent rationale and reversal path.

## F4 — Optional CoreFlow integration

- Document capability discovery and authority model.
- Prefer standard APIs; introduce versioned ABI only with demonstrated need.
- Test stock kernel + CoreFlow, Umbrella alone, and Umbrella + CoreFlow.

**Release rule:** do not call an artifact production-ready or safe to flash without hardware validation.
