# Umbrella Project

**Independent Android kernel engineering for Redmi Note 15 5G.**

Umbrella Project is a Mystivara initiative to develop **Umbrella Kernel** as a device-specific Android/Linux kernel focused on reliability, measurable responsiveness, and energy efficiency. It is designed to optionally cooperate with **CoreFlow Autonomous Engine**.

> **Current status: Reproducible build / compatibility verification.** The pipeline assembles SHA-pinned Xiaomi kunzite and Android GKI sources. Build verification and stock vendor ABI compatibility are separate gates; no artifact is approved for flashing.

> **Hardware update (2026-10-31): core-test01 is withdrawn.** Temporary boot was
> accepted by fastboot, but Android did not reach the home screen. Normal reboot
> restored the original kernel. See the [test01 audit](docs/TEST01_AUDIT.md);
> further hardware trials are paused while module loading is investigated.

## Objectives

- Build and maintain an independently managed kernel source repository using the correct device/vendor upstream baseline, with original attribution retained.
- Prioritize hardware compatibility, stable frame delivery, responsive app launching, memory/I/O consistency, thermal safety, and power efficiency.
- Establish repeatable stock-equivalent benchmarks before making optimization claims.
- Support optional, runtime-discovered interoperability with [CoreFlow Engine](https://github.com/mystivara-creator/CoreFlow-Engine); neither project must require the other to function.

## Repository layout

```text
Umbrella-Project/
├── config/devices/          Device identity manifests (unverified template initially)
├── docs/                    Architecture, bring-up, roadmap, source policy
├── interfaces/              Draft optional integration contracts
├── tools/                   Workspace assembly, source and artifact/ABI verification
├── tests/                   Build pipeline and compatibility regression tests
├── .github/workflows/       Kleaf kernel build and validation
├── README.md
└── .gitignore
```

A real Linux kernel source tree (e.g. `arch`, `drivers`, `include`, `kernel`, `mm`) will only be added **after** a compatible kernel source and licensing obligations are verified.

## Architecture

```text
mystivara-creator/
├── Umbrella-Project/
│   ├── arch/
│   ├── drivers/
│   ├── include/
│   ├── kernel/
│   ├── mm/
│   ├── Documentation/
│   └── docs/
│
├── Android-Kernel-Builder/
│   └── .github/workflows/
│
└── CoreFlow-Engine/
```

## Development milestones

1. Confirm exact device variant, firmware, kernel, partition scheme and recovery path.
2. Locate matching Xiaomi/vendor sources and pin upstream source revisions.
3. Reproduce a stock-equivalent kernel build with strict artifact validation.
4. Verify safe boot, vendor module compatibility, peripheral behavior, and regressions.
5. Introduce independently benchmarked improvements with clear rollback plans.
6. Implement an optional, versioned Umbrella–CoreFlow capability interface only where standard interfaces are insufficient.

See [Architecture](docs/ARCHITECTURE.md), [Bring-up](docs/DEVICE_BRINGUP.md), [Roadmap](docs/ROADMAP.md), and [Source policy](docs/SOURCE_POLICY.md).

## Validation

Run the metadata checks and host regression suite locally:

```sh
python3 tools/validate_foundation.py
python3 tools/validate_device_baseline.py
python3 tools/source_audit.py
python3 tools/validate_regions.py
python3 -m unittest discover -s tests -v
```

The **Umbrella Kernel Build** workflow builds ARM64 GKI and vendor outputs. Its
artifact verifier checks vendor and GKI critical Kconfig options independently,
rejects invalid AArch64 module metadata, and writes `umbrella-build-report.json`.
Run it locally against downloaded dist outputs with:

```sh
python3 tools/verify_build_artifacts.py --dist-dir /path/to/dist
```

Supply `--stock-module-baseline /path/to/stock-module-metadata.json` to compare
stock imported symbol CRCs with built exports. Use `--require-compatibility` to
fail on unresolved compatibility blockers. Passing host tests or the build gate
does not certify device compatibility; `flash_approved` remains `false`.

## Safety and licensing

Do not flash unverified images. Kernel development can cause failure to boot and data loss. Upstream code and modifications are subject to their applicable licenses and source distribution obligations. A project-level license for original materials should be decided separately after source provenance is established.

Umbrella Project is an independent software effort, not affiliated with Xiaomi, Capcom, or Umbrella Corporation from Resident Evil.

