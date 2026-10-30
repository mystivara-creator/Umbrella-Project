# core-test01: withdrawn after incomplete Android boot

Status recorded 2026-10-31, Asia/Jakarta. Hardware trials and permanent flashing
are paused. This document distinguishes observations from possible causes.

## Device observations

- Fastboot reported product `kunzite`, `is-userspace: no`, and successful image
  transfer plus `Booting OKAY`. This establishes acceptance of the command,
  not successful Android boot or even the running kernel identity.
- Android did not reach the home screen after approximately three minutes at
  the Xiaomi HyperOS logo. A different initial logo sequence was reported.
  Neither observation identifies a specific kernel fault.
- A normal restart returned to
  `6.6.118-android15-8-ge56cf6b09cca-ab15511674-4k` with root access.
  `/sys/fs/pstore` was empty. There is no crash trace proving the cause.
- No permanent partition flash was performed for this trial.

Withdrawn boot image SHA-256:
`39aaf7a7acbe8f8d7cee4c940f01f65e40d5fe590f2ce1a216ac5b973ba91bfc`.

Its kernel SHA-256:
`d051a92068dd5c33ce33fc543f5959140b963d6f68432a9cc8813f680e642bdf`.

The earlier archive and generation report are historical artifacts; their
host-side checks must not be interpreted as a successful hardware test.

## Confirmed audit gaps

1. **Signing key continuity was not checked.** Both running-stock and built
   GKI configurations enable `CONFIG_MODULE_SIG_PROTECT=y`. Each uncompressed
   Image contains one parseable X.509 certificate at offset 34,446,080, length
   1,357 bytes, but their public keys differ. SPKI DER SHA-256:
   - Stock: `0c0c619ed5e0ec136f7acf2e0e997ea5b236a2089c1d6a21074fab0629cf4acd`
   - Built: `c01291a06984f37a2189ae6572b2031e9b5306dc14c86498ac04867df5de9729`
   The candidate retained stock GKI modules. A matching CRC does not establish
   that their signatures remain trusted or that protected exports are usable.
   Finding a certificate inside Image also does not prove its keyring membership.
2. **Loaded-module import coverage is incomplete.** The metadata has 362
   modules, while the original runtime has 443 loaded modules. Exactly 102
   loaded names lack import metadata; 341 loaded names are covered. The extra
   baseline entries describe modules not loaded at collection time. None of
   the 102 missing names occurs in the collected filesystem module paths.
   Examples include `clk_qcom`, `qcom_scm`, `ufs_qcom`, `sched_walt`, `metis`
   and `kernelsu`. Inspecting the early boot ramdisk is the next collection
   step; their absence from dlkm indices is not proof of their storage location.

## Relevant upstream behavior

The pinned ACK revision is
`e56cf6b09cca2151bcee244b3d334fb68685ff57`. Primary source references:

- [MODULE_SIG_PROTECT contract](https://github.com/aosp-mirror/kernel_common/blob/e56cf6b09cca2151bcee244b3d334fb68685ff57/kernel/module/Kconfig)
- [Signature checking and sig_ok](https://github.com/aosp-mirror/kernel_common/blob/e56cf6b09cca2151bcee244b3d334fb68685ff57/kernel/module/signing.c)
- [Protected export and symbol-access checks](https://github.com/aosp-mirror/kernel_common/blob/e56cf6b09cca2151bcee244b3d334fb68685ff57/kernel/module/main.c)
- [Generated allow/protection lists](https://github.com/aosp-mirror/kernel_common/blob/e56cf6b09cca2151bcee244b3d334fb68685ff57/kernel/module/gki_module.c)
- [GKI target protection settings](https://github.com/aosp-mirror/kernel_common/blob/e56cf6b09cca2151bcee244b3d334fb68685ff57/BUILD.bazel)

Under this policy, a module whose signature is not trusted is treated as a
vendor module. Its access to protected symbols and its export of GKI-protected
symbols can fail with EACCES, even with matching CRCs and SIG_FORCE disabled.
This is a concrete omitted compatibility check and a plausible boot blocker;
it is **not a confirmed diagnosis** of this device's stalled boot.

## Changes and remaining work

`tools/audit_core_module_policy.py` checks loaded-name coverage and compares
embedded certificate public keys. The preparer now requires those checks before
writing a boot candidate. Against the supplied inputs it fails on both gaps.
OpenSSL is required; renewed certificates with the same key are compared by
public key rather than certificate hash. A passing host check still leaves
`module_loading_verified=false` and `flash_approved=false`.

Read-only reproduction (exit status 1 is expected for build14):

```sh
python3 tools/audit_core_module_policy.py \
  --device-baseline /path/to/unpacked-device-baseline \
  --stock-modules /path/to/abi-baseline-combined.json \
  --dist-dir /path/to/build-dist \
  --report-out /path/to/module-policy-report.json
```

Before another device trial:

1. Inspect active vendor_boot/init_boot offline to obtain early-module imports,
   signatures, dependencies, load lists and the actual root-loading arrangement.
2. Verify the actual stock GKI module signatures against the stock public key,
   and establish the candidate's trusted keyring contents and generated symbol
   access lists. Evaluate retaining the verified stock public certificate in
   the build's trusted keyring, or a coherent rebuilt GKI module set; neither
   option is implemented or qualified by this audit.
3. Check remaining boot layout, module namespace/license requirements and
   dependency order. The v4 empty ramdisk, original header preservation and
   unsigned AVB hash checks already performed do not establish acceptance of
   the complete boot chain or explain the observed hang.
4. Establish diagnostics that can operate before the failing boot stage. A
   KernelSU service.d recorder is verified only on the original kernel; it may
   never run if the candidate cannot load KernelSU or reach late userspace.

Do not disable signature protection, force module loads or spoof CRCs/version
strings to turn these checks green. No new image is approved by this audit.

## Follow-up with early ramdisk evidence

The additional baseline has now been inspected. Metadata covers 442 loaded
module names with CRCs, and locates the separate KernelSU LKM; no core CRC
mismatch was found in that expanded scope. The observed protection arrays
also agree between stock and candidate. See [boot failure investigation](BOOT_FAILURE_ANALYSIS.md)
for sources, exact scope and remaining signature/runtime evidence. The
original trial still has no confirmed root-cause diagnosis or flash approval.
