# Upstream Kernel Sources, Revisions, and License Provenance

This document records the exact upstream repositories, pinned revisions, license
obligations, and architectural boundaries required by `docs/SOURCE_POLICY.md`
before importing a Linux kernel source tree into `Umbrella-Project`.

## 1. Pinned Upstream Components (`kunzite` / `parrot` SM6475)

| Component | Role in Kleaf Mixed Build | Upstream Repository | Branch / Lineage | Pinned Commit (SHA-1) | Primary License |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `common_kernel` | Core GKI `Image` (`vmlinux`), `boot.img`, `system_dlkm`, frozen `android15-8` KMI (`Linux 6.6.118`) | `https://android.googlesource.com/kernel/common` | `android15-6.6` | `e56cf6b09cca2151bcee244b3d334fb68685ff57` | `GPL-2.0 WITH Linux-syscall-note` (`COPYING`, `LICENSES/`) |
| `msm_kernel` | Qualcomm `parrot` + Xiaomi `kunzite` in-tree vendor `.ko` modules & Kleaf target rules (`Linux 6.6.56`) | `https://github.com/MiCode/Xiaomi_Kernel_OpenSource.git` | `kunzite-v-oss` | `2d446f1cf9e3a18c30af43ebeb6e5a443636d647` | `GPL-2.0 WITH Linux-syscall-note` (`COPYING`, `LICENSES/`) |
| `kernel_devicetree` | Qualcomm `parrot`/`ravelin` base `.dtb` + `kunzite-sm6475-overlay.dtbo` (`msm-kernel/arch/arm64/boot/dts/vendor`) | `https://github.com/MiCode/kernel_devicetree.git` | `kunzite-v-oss` | `135826dc58add57c7cfdcf01e3c4bb8d9f2cf36f` | `GPL-2.0-only` / dual-licensed DTS headers |
| `kernel_build` | Xiaomi/Qualcomm Kleaf build rules (`build/kernel`) | `https://github.com/MiCode/kernel_build.git` | `kunzite-v-oss` | `d0c9ebb3187e9b5159b753f989624978435db516` | `Apache-2.0` |
| `external_dtc` | Device Tree Compiler (`@dtc` at `external/dtc`) | `https://git.codelinaro.org/clo/la/kernel_platform/external/dtc.git` | `kernel.build.lnx.2.0.r50-rel` | `abee18fa51c1ffdd58d5b481fb82735dfa6b8a2d` | `GPL-2.0-or-later` / `BSD-2-Clause` |

## 2. In-Repo Kernel Source Tree Architecture

On Redmi Note 15 5G (`kunzite`, `OS3.0.304.0.WPQMIXM`), `define_kunzite()` in
`kunzite.bzl` invokes `define_msm_la()` (`msm_kernel_la.bzl`) using Qualcomm's
Kleaf mixed-build split:

1. **`//common:kernel_aarch64` (`common_kernel`, Linux `6.6.118-android15-8`)**
   compiles the actual running kernel `Image` (`vmlinux`) inside `boot.img` and
   core GKI modules:
   - `arch/arm64/` core architecture code
   - `kernel/` (EEVDF/CFS scheduler, locking, RCU, `kernel/module/signing.c`, `gki_module.c`)
   - `mm/` (MGLRU, page reclaim, ZRAM/zsmalloc, allocator paths)
   - `block/` and `fs/` (I/O stack, F2FS, EROFS, ext4)
   - `certs/` (`.builtin_trusted_keys` under `CONFIG_MODULE_SIG_PROTECT=y`)
   - `drivers/` (core GKI drivers) and `include/`
2. **`//msm-kernel:kunzite_perf` (`msm_kernel` + `kernel_devicetree`)** sets
   `base_kernel = "//common:kernel_aarch64"` and `build_boot = False`. It does
   **not** link its `6.6.56` core `mm/` or `fs/` into `Image`; instead, it
   compiles Qualcomm/Xiaomi vendor `.ko` modules (`sched-walt.ko`,
   `qcom-cpufreq-hw.ko`, `clk-qcom.ko`, `ufs_qcom.ko`, `xiaomi_fp.ko`, etc.) and
   `kunzite` DTBs/DTBOs against `//common:kernel_aarch64`'s KMI exports.

### Recommended Root Tree (`--role common`)

Importing `common_kernel@e56cf6b09cca2151bcee244b3d334fb68685ff57` as the root
tree of `Umbrella-Project` places the real `6.6.118` `arch/`, `drivers/`,
`include/`, `kernel/`, `mm/`, `fs/`, `block/`, `certs/`, `COPYING`, `Makefile`,
and `BUILD.bazel` directly at the repository root:

- Direct commits in `Umbrella-Project` to `arch/`, `kernel/`, `mm/`, `drivers/`,
  `fs/`, `block/`, or `certs/` compile straight into `//common:kernel_aarch64`
  (`Image` + GKI modules).
- Modifications to Qualcomm/Xiaomi vendor modules or `kunzite` device trees are
  maintained as ordered, auditable `git format-patch` series in
  `patches/msm-kernel/` and `patches/kernel_devicetree/`, applied
  deterministically during `tools/setup_kleaf_workspace.py`.
- `tools/import_kernel_tree.py` also supports `--role msm-kernel` if a
  vendor-driver-rooted layout (`MiCode/Xiaomi_Kernel_OpenSource@2d446f1cf9e3` +
  `arch/arm64/boot/dts/vendor` @ `135826dc58ad`, with `patches/common/`) is
  explicitly selected.

## 3. Licensing, Attribution, and KMI Safety Rules

- **Preserve Upstream Attribution**: Never strip `SPDX-License-Identifier` tags,
  copyright headers, `COPYING`, `CREDITS`, `MAINTAINERS`, or `LICENSES/`.
- **Source Distribution**: Any distributed binary `Image` or `.ko` built from
  GPLv2-covered kernel sources carries full corresponding source obligations
  under `GPL-2.0 WITH Linux-syscall-note`.
- **No Proprietary Blobs**: Never commit extracted stock `.ko` binaries,
  `boot-backup.img`, `vendor_boot-backup.img`, or OEM private keys into Git.
- **Frozen KMI Discipline**: Modifications to `include/` or core kernel structs
  must not alter exported `android15-8` KMI symbol CRCs (`CONFIG_MODVERSIONS=y`)
  consumed by retained on-device modules, and must satisfy both
  `tools/audit_stock_module_abi.py` and `tools/audit_core_module_policy.py`
  before any hardware boot candidate is generated.
