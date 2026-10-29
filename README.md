# Umbrella Project

**Independent Android kernel engineering for Redmi Note 15 5G.**

Umbrella Project is a Mystivara initiative to develop **Umbrella Kernel** as a device-specific Android/Linux kernel focused on reliability, measurable responsiveness, and energy efficiency. It is designed to optionally cooperate with **CoreFlow Autonomous Engine**.

> **Current status: Foundation / source identification.** This repository does not yet contain a validated kernel source, build, or flashable artifact.

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
├── tools/                   Foundation validation (no kernel compilation)
├── .github/workflows/       Documentation and manifest validation
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

The included validation checks only the **foundation metadata**; it does not build, test, or certify a kernel:

```sh
python3 tools/validate_foundation.py
```

## Safety and licensing

Do not flash unverified images. Kernel development can cause failure to boot and data loss. Upstream code and modifications are subject to their applicable licenses and source distribution obligations. A project-level license for original materials should be decided separately after source provenance is established.

Umbrella Project is an independent software effort, not affiliated with Xiaomi, Capcom, or Umbrella Corporation from Resident Evil.
