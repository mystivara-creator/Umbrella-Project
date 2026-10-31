# Boot failure investigation: evidence from the early ramdisks

Recorded 2026-10-31 (Asia/Jakarta). core-test01 remains withdrawn. No new device
trial or partition write is requested by this investigation. A rule established
from upstream source is not itself proof that the rule caused this phone's hang.

## Inputs verified

All 24 SHA256SUMS entries in the newly supplied private baseline archive verify.
The active boot backup is byte-identical to the previous backup, SHA-256
`4ec2b6b9f4cb93a760107eceaa79ad7eabab9a5559b3c73fdece83b0f9c9431d`.
Additional active-slot backups:

| Image | SHA-256 |
| --- | --- |
| vendor_boot | `0c60778b96c0cd3a9b7bc0af61bdb1c4f69480a1d331e62d37803eca268b21df` |
| init_boot | `d8fbed2cd0cc925c860e7edbc1b9eec28bed049abb715ff0038517cd67ebd329` |

The v4 vendor boot image contains one platform ramdisk, a DTB payload and
bootconfig. Its legacy-LZ4/newc ramdisk contains 287 .ko files, dependency lists
and modules.load. The separate init_boot ramdisk contains one kernelsu.ko,
the replacement init, init.real and ksu_config (`bundled=1`). Proprietary images
and module binaries are not included in this repository.

## Results that narrow the investigation

- **Compiler mismatch is not supported by the binaries.** Both Linux banners
  identify the exact same Android clang/LLD 18.0.0 build 11368308, r510928,
  LLVM revision `477610d4d0d988e69dbc3fae4fe86bff3f07f2b5`. Their release
  suffix and build timestamp differ; those differences do not prove the hang.
- **The earlier 102-name coverage gap has been located.** The ramdisk modules
  supply metadata for every previously uncovered loaded name. Across the
  supplied dlkm metadata and these ramdisks, 442 of 443 loaded names have
  imported CRC metadata. kernelsu.ko has an empty __versions section and is
  examined separately; it must not be silently counted as a CRC pass.
- **No core CRC failure was found in that 442-name scope.** There are 25,467
  distinct per-module import entries: 22,706 core CRC matches and 2,761 edges
  to retained stock-module providers. Duplicate same-name records were merged
  only when shared symbol CRCs agreed. The system and ramdisk zram variants
  have different import sets; their union was checked, rather than silently
  selecting one. This checks metadata, not live module initialization.
- **Early unsigned-module symbol access is not a demonstrated failure.** All
  287 vendor-ramdisk modules lack an appended module signature. The sorted
  fixed-width symbol arrays recovered from stock and candidate Image contain
  the same 507 protected exports and 9,286 unprotected symbols. The protected
  array exactly matches the pinned upstream protected-exports file. No core
  import from the 287 ramdisk modules falls outside the candidate unprotected
  array, and none exports a name in its protected-export array.
- **BTF mismatch alone is not a supported diagnosis.** The configuration has
  `CONFIG_MODULE_ALLOW_BTF_MISMATCH=y`. The pinned BTF notifier can warn and
  continue when module BTF cannot be validated under this option. This does
  not rule out every possible BTF-related problem.
- **KernelSU's raw vermagic is not enough to blame root.** The ramdisk LKM has
  `6.6.127-4k-g46a034eca005-dirty` vermagic, no CRC entries, and 227 undefined
  ELF symbols. The installed replacement init contains strings for kallsyms
  resolution and vermagic retry. The examined KernelSU-Next source implements
  those operations. Therefore ordinary modprobe/version assumptions cannot
  certify this LKM or prove it caused the hang. Its exact source revision and
  successful operation on the candidate remain unverified.

## Primary source basis

The first six kernel links use the **exact ACK revision used by the build**,
`e56cf6b09cca2151bcee244b3d334fb68685ff57`, not advice from another phone:

1. [Android module signature and protected-symbol policy](https://github.com/aosp-mirror/kernel_common/blob/e56cf6b09cca2151bcee244b3d334fb68685ff57/kernel/module/main.c)
   checks `sig_ok` before allowing access to protected symbols or protected
   exports; a CRC match does not bypass these rules.
2. [Signature checker](https://github.com/aosp-mirror/kernel_common/blob/e56cf6b09cca2151bcee244b3d334fb68685ff57/kernel/module/signing.c)
   sets `sig_ok` only after successful signature verification.
3. [Protection array generator](https://github.com/aosp-mirror/kernel_common/blob/e56cf6b09cca2151bcee244b3d334fb68685ff57/scripts/gen_gki_modules_headers.sh)
   emits sorted, fixed-width character arrays, which permits comparison with
   the actual arrays in the two uncompressed kernel binaries.
4. [Module-signing documentation](https://github.com/aosp-mirror/kernel_common/blob/e56cf6b09cca2151bcee244b3d334fb68685ff57/Documentation/admin-guide/module-signing.rst)
   documents additional trusted public certificates through
   `CONFIG_SYSTEM_TRUSTED_KEYS`; an OEM private signing key is not needed to
   retain a public verification certificate.
5. [Certificate build rules](https://github.com/aosp-mirror/kernel_common/blob/e56cf6b09cca2151bcee244b3d334fb68685ff57/certs/Makefile)
   and [system keyring loader](https://github.com/aosp-mirror/kernel_common/blob/e56cf6b09cca2151bcee244b3d334fb68685ff57/certs/system_keyring.c)
   show how configured public certificates reach the compiled-in keyring.
6. [BTF module notifier](https://github.com/aosp-mirror/kernel_common/blob/e56cf6b09cca2151bcee244b3d334fb68685ff57/kernel/bpf/btf.c)
   implements the configured BTF mismatch handling.
7. [AOSP Android 16 first-stage init](https://github.com/aosp-mirror/platform_system_core/blob/android-16.0.0_r1/init/first_stage_init.cpp)
   reads early module load lists, tries release-specific directories and can
   fall back to matching major/minor directories and `/lib/modules`. This
   describes AOSP behavior, not proof of Xiaomi's exact shipped init behavior.
8. [KernelSU-Next loader](https://github.com/KernelSU-Next/KernelSU-Next/blob/8979126b66aa8cd503071ffb98df8ec5c7a78742/userspace/ksuinit/src/lib.rs)
   resolves undefined symbols from kallsyms and can retry module loading after
   adjusting vermagic. This is the inspected upstream revision, not a claim
   that the phone's binary was built from that exact commit.

## Remaining evidence and supported repair route

The subsequently supplied stock bluetooth.ko now proves a module-trust
incompatibility in the withdrawn candidate. Its PKCS#7 signature verifies
against the certificate extracted from the stock kernel; the certificate in
the candidate cannot resolve its signer. It exports 54 symbols protected by
the candidate. A one-byte content modification is correctly rejected by the
stock-certificate verification. See [verified trust failure and repair](GKI_MODULE_TRUST_FIX.md).

The source repair retains the exact verified stock **public** certificate in
the candidate keyring through CONFIG_SYSTEM_TRUSTED_KEYS, with signature
protection enabled. Build verification now checks its exact certificate and
public-key fingerprints and the embedded configuration. A newly compiled
Image still needs those checks; no hardware result is implied by the source
patch, and the Android boot hang remains a separate unconfirmed diagnosis.

The stalled boot still has no captured failed-boot kernel/userspace log and no
confirmed running-candidate identity. Root persistence, module initialization,
Android service startup and the complete temporary-boot chain therefore remain
unproven. Keep hardware trials paused; do not use a permanent flash as a
diagnostic substitute.
