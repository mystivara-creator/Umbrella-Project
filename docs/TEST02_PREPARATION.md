# core-test02: offline preparation, device trial paused

This is a reviewable temporary-boot candidate, not a flash release. No second
hardware boot trial has occurred. The failed core-test01 kernel trace remains
unavailable: the normal-boot early log and later dmesg are not failed-boot logs.

## Qualification and remaining uncertainty

The rebuilt Image from CI commit
`a201edb6b8c30791fb302d44c9d5d5dc8aa878a6` retains the exact stock module
certificate and verifies the supplied stock Bluetooth module signature. Its
SHA-256 is `9bd768b41daa60a10ddc95b1b6611d1739b9332d14e2d95c5c373662b9037a0d`.

The combined dlkm and vendor-ramdisk metadata has 463 unique native module
names, covering the 442 loaded native names plus modules not loaded at the
stock snapshot. All 26,332 import entries are accounted for: 23,385 core CRC
matches and 2,947 edges to retained module providers. Same-name variants are
merged only when shared CRCs agree; the differing zram import sets are both
covered. All 649 native source records have matching vermagic flags after
the release token. No module binary or raw private log is committed here.

KernelSU is separate. The stock early log shows ksuinit loading LKM version
33355 around 0.344 seconds and handing control to init.real. Missing
module_layout CRC and BTF-mismatch warnings occur during this successful
stock boot. They do not prove a candidate failure. The stock kernel also
registers a ramoops console around 0.064 seconds, before KernelSU loads.

The stock and candidate base BTF have the same strings and type counts, but
different type-ID references. A comparison independent of these IDs found no
differences in direct named structure/union layouts across 10,650 names. Of
the LKM's 227 undefined references, 203 have matching comparable BTF types;
24 do not have comparable BTF records. This does not prove machine-code
equivalence, complete internal ABI compatibility or safe runtime hook behavior.

## Explicit preparation scope

The default preparer still rejects a missing loaded-module CRC baseline.
The optional `--allow-stock-kernelsu-lkm-for-temporary-boot` mode accounts for
exactly one different loading mechanism. It requires the exact reviewed Image,
stock boot, stock init_boot, LKM and working-stock early log hashes recorded
in `config/testing/kunzite-core-test02.json`. init_boot must be covered by the
collected baseline checksums. No other missing native module is exempted.

This mode records `native_crc_pass=false` and `target_runtime_verified=false`
for the dynamic LKM, while retaining the full native CRC and signing checks.
It never marks the versionless LKM as a CRC success. A different kernel build,
different root snapshot or additional uncovered driver fails preparation.
All output candidates retain `hardware_tested=false` and `flash_approved=false`.

Reproduction needs the same private baseline inputs and full native metadata:

```sh
python3 tools/prepare_core_test.py \
  --device-baseline /path/to/qualified-baseline \
  --stock-modules /path/to/full-native-module-metadata.json \
  --dist-dir /path/to/a201edb-dist \
  --avbtool /path/to/pinned-avbtool.py \
  --allow-stock-kernelsu-lkm-for-temporary-boot \
  --stock-kernelsu-module /path/to/extracted-stock/kernelsu.ko \
  --stock-early-log /path/to/working-stock/dmesg-start.txt \
  --output-dir /path/to/new-output-directory
```

The prepared boot image SHA-256 is
`0f153a923f3490661e268c86473603ffcf215d6e7faeec8189eacbd73db6c84a`.
Its v4 header, empty ramdisk and 96 MiB size were checked, the AVB hash was
verified, and an independent unpack produced the exact expected Image bytes.
vendor_boot, init_boot, dtbo, vbmeta and module partitions are retained.

## Before considering a hardware trial

The installed OrangeFox needs a read-only preflight: recovery kernel identity,
pstore support/backend and access to the intended output storage after data
decryption. A directory existing or being empty does not establish persistent
log recovery across a failed boot and reset. No such recovery test has yet
been performed.

`tools/collect_recovery_pstore.sh` only archives records already visible in
/sys/fs/pstore. It does not mount filesystems, clear records, reboot, change
slots or flash partitions. If a later authorized trial stalls, the intended
diagnostic route is recovery before another Android boot, preserving any
available prior-kernel console. Availability through the installed recovery
and reset path remains a qualification item, not a guarantee.

43 host tests passed, including rejection of an unreviewed Image, additional
uncovered modules and an unchecked init_boot. Default-mode rejection was
confirmed against the actual inputs before creating this explicitly scoped
candidate. The user's pause on hardware trials remains in effect.
