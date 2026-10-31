# Verified stock GKI module trust incompatibility

The user-supplied stock bluetooth.ko establishes a concrete incompatibility in
core-test01. It does not establish that this is the sole cause, or the cause,
of the observed incomplete Android boot. Hardware trials remain paused.

## Evidence

| Check | Result |
| --- | --- |
| Module SHA-256 | `3abdfc401218a233fe2f01d06e747c32bbbc1bd1204f989b298859f3f6f6fc04` |
| Module bytes | 1,266,377 |
| Signed content bytes | 1,265,656 |
| Appended PKCS#7 bytes | 681 |
| Signature using stock Image certificate | verified |
| Signer lookup using candidate Image certificate | failed: signer certificate not found |
| One-byte content modification using stock certificate | rejected |
| bluetooth.ko exports protected in the candidate | 54 of 54 exports |

Verification uses OpenSSL CMS with detached binary content and `-nointern` to
force the explicitly selected certificate. `-noverify` skips PKI chain building;
it does **not** skip verification of the content signature. The trusted
certificate is selected from the already qualified stock backup, not accepted
from an arbitrary signer embedded in the supplied module. Both the certificate
and public-key fingerprints are pinned in the source manifest.

The candidate has MODULE_SIG_PROTECT enabled and a different built-in signing
certificate. In the pinned ACK loader, failure to establish `sig_ok` restricts
protected symbol access/exports. bluetooth.ko therefore cannot be treated as a
working retained GKI module on the withdrawn candidate merely because CRCs
match. Its protected exports constitute a concrete loadability blocker.

Relevant exact upstream sources:

- [Signature verification](https://github.com/aosp-mirror/kernel_common/blob/e56cf6b09cca2151bcee244b3d334fb68685ff57/kernel/module/signing.c)
- [Protected exports and symbol access](https://github.com/aosp-mirror/kernel_common/blob/e56cf6b09cca2151bcee244b3d334fb68685ff57/kernel/module/main.c)
- [Additional trusted public certificates](https://github.com/aosp-mirror/kernel_common/blob/e56cf6b09cca2151bcee244b3d334fb68685ff57/Documentation/admin-guide/module-signing.rst)
- [Certificate compilation](https://github.com/aosp-mirror/kernel_common/blob/e56cf6b09cca2151bcee244b3d334fb68685ff57/certs/Makefile)
- [Compiled-in keyring loader](https://github.com/aosp-mirror/kernel_common/blob/e56cf6b09cca2151bcee244b3d334fb68685ff57/certs/system_keyring.c)

## Source repair

`patches/common_kernel/0001-retain-kunzite-stock-module-trust.patch` adds the
exact stock public certificate to `certs/umbrella-kunzite-stock.pem` and selects
it using CONFIG_SYSTEM_TRUSTED_KEYS in the ARM64 GKI defconfig. It retains the
normal build-generated module-signing key and MODULE_SIG_PROTECT. No private
stock key is available, required or committed. No stock .ko or partition image
is committed either.

The source manifest records the public certificate, public key, source patch,
stock boot backup and verified representative module hashes. Source auditing
checks the maintained certificate and patch checksums. Workspace assembly
checks that the actual common kernel source has the expected certificate and
GKI defconfig setting. Importing a common tree applies the maintained common
patch series before binding it as an in-repository source tree.

Artifact verification reads IKCONFIG from the actual produced Image and checks
the configured trust path, module signature verification/protection, trusted
keyring option, and the presence of the exact stock certificate and public key.
This is an exact certificate check, not just a match on its subject name or an
arbitrary renewed certificate sharing a key. The preparer permits the specified
trust configuration delta only after the Image check passes; all other ABI,
coverage, boot and hardware restrictions continue to apply.

The patch was applied and checked against the exact pinned ACK defconfig in a
local fixture and its second application was recognized as already applied.
All 40 host tests and four metadata audits passed before submission. The
cryptographic checks above used the actual uploaded module; it is not included
as a test fixture in Git.

## Remaining qualification

A successful rebuild must demonstrate that Kleaf preserved the configured
certificate and embedded configuration. That artifact is still an engineering
build: KernelSU's dynamically resolved module, complete runtime startup and
the cause of the observed hang remain unverified. The new source patch does
not grant flash approval or claim a successful device boot.

## Successful rebuild and independent artifact check

[CI run 41180772543](https://github.com/mystivara-creator/Umbrella-Project/actions/runs/41180772543)
completed successfully for `a201edb6b8c30791fb302d44c9d5d5dc8aa878a6`.
The downloaded artifact archive matches GitHub's SHA-256 digest
`d976960dde6ae8b84bc33503382f82416c621605f7ef4c9cdcd1db324a9a878d`.

The new kernel Image SHA-256 is
`9bd768b41daa60a10ddc95b1b6611d1739b9332d14e2d95c5c373662b9037a0d`.
It contains two X.509 certificates, including the exact qualified stock
certificate. The actual certificate extracted from this new Image successfully
verifies the supplied bluetooth.ko content signature. Thus the signing-anchor
discontinuity found in core-test01 is corrected in the compiled artifact.

The expanded 442-module CRC scope was rerun against the new GKI export table:
22,706 core matches, 2,761 retained-provider imports, zero findings. The only
Kconfig differences from the original running kernel are the two previously
qualified debug-compression options and the specified SYSTEM_TRUSTED_KEYS path.

These checks do not qualify the separately loaded KernelSU LKM or establish
successful Android startup. A complete boot candidate, usable failed-boot
diagnostics and subsequent controlled hardware boot qualification are still
required; permanent flashing is not approved.
