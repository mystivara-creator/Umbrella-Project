#!/system/bin/sh
# Read-only Android baseline collection for a kernel-only test candidate.
# Run with root. No partition, setting, or module is modified.
set -eu

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
include_early_boot=0
case "$#:${1:-}" in
    0:) ;;
    1:--include-early-boot) include_early_boot=1 ;;
    *) fail 'Usage: collect_test_baseline.sh [--include-early-boot]' ;;
esac
for tool in id getprop uname dd mktemp mkdir find cp awk sort tar gzip sha256sum \
    tr dirname chmod date rm; do
    command -v "$tool" >/dev/null 2>&1 || fail "Required command unavailable: $tool"
done
[ "$(id -u)" = 0 ] || fail 'Run this script through su.'
device=$(getprop ro.product.device)
[ "$device" = kunzite ] || fail "Expected kunzite, found $device"
slot=$(getprop ro.boot.slot_suffix)
case "$slot" in ''|_a|_b) ;; *) fail "Unexpected slot suffix: $slot" ;; esac

boot=
for base in /dev/block/by-name /dev/block/bootdevice/by-name; do
    if [ -b "$base/boot$slot" ]; then boot="$base/boot$slot"; break; fi
done
[ -n "$boot" ] || fail 'Active boot block device not found; nothing was copied.'

workdir=$(mktemp -d /data/local/tmp/umbrella-baseline.XXXXXX)
trap 'rm -rf "$workdir"' EXIT
trap 'exit 1' HUP INT TERM
mkdir -p "$workdir/metadata"
{
    for key in ro.product.device ro.product.model ro.build.fingerprint \
        ro.vendor.build.fingerprint ro.bootimage.build.fingerprint \
        ro.build.version.release ro.build.version.security_patch \
        ro.boot.slot_suffix ro.boot.flash.locked ro.boot.vbmeta.device_state \
        ro.boot.verifiedbootstate; do
        printf '%s=%s\n' "$key" "$(getprop "$key")"
    done
    printf 'kernel.release=%s\n' "$(uname -r)"
    printf 'kernel.arch=%s\n' "$(uname -m)"
    printf 'backup.boot.device=%s\n' "$boot"
    printf 'baseline.format_version=1\n'
} > "$workdir/device.properties"

printf 'Backing up active boot partition: %s\n' "$boot"
dd if="$boot" of="$workdir/boot-backup.img" bs=1048576
[ "$(dd if="$workdir/boot-backup.img" bs=8 count=1 2>/dev/null)" = 'ANDROID!' ] \
    || fail 'Backup does not have an Android boot header.'

# Early modules need not remain visible in mounted dlkm directories after boot.
# Optional backups permit offline ramdisk inspection; no partition is written.
if [ "$include_early_boot" = 1 ]; then
    for kind in vendor_boot init_boot; do
        partition=
        for base in /dev/block/by-name /dev/block/bootdevice/by-name; do
            if [ -b "$base/$kind$slot" ]; then
                partition="$base/$kind$slot"
                break
            fi
        done
        if [ -z "$partition" ]; then
            [ "$kind" = init_boot ] && continue
            fail "Active $kind partition not found"
        fi
        printf 'Backing up active %s partition: %s\n' "$kind" "$partition"
        dd if="$partition" of="$workdir/$kind-backup.img" bs=1048576
        magic=$(dd if="$workdir/$kind-backup.img" bs=8 count=1 2>/dev/null)
        case "$kind:$magic" in
            vendor_boot:VNDRBOOT|init_boot:ANDROID!) ;;
            *) fail "Unexpected $kind image header" ;;
        esac
        printf 'backup.%s.device=%s\n' "$kind" "$partition" >> "$workdir/device.properties"
    done
fi

# Keep both depmod indices and loaded export ownership. Early-boot modules
# need not be present in vendor_dlkm, so indices alone are insufficient.
for module_root in /lib/modules /vendor/lib/modules /system/lib/modules \
    /vendor_dlkm/lib/modules /system_dlkm/lib/modules \
    /odm/lib/modules /odm_dlkm/lib/modules; do
    [ -d "$module_root" ] || continue
    label=$(printf '%s' "$module_root" | tr / _)
    destination="$workdir/metadata/$label"
    mkdir -p "$destination"
    find -L "$module_root" -type f \( -name modules.symbols -o \
        -name modules.dep -o -name modules.load -o -name modules.blocklist \) \
        > "$workdir/indices.list"
    while IFS= read -r entry; do
        relative=${entry#"$module_root"/}
        case "$relative" in /*|../*|*/../*) fail 'Unexpected module index path' ;; esac
        mkdir -p "$destination/$(dirname "$relative")"
        cp "$entry" "$destination/$relative"
    done < "$workdir/indices.list"
    find -L "$module_root" -type f -name '*.ko*' > "$destination/module-files.txt"
done
rm -f "$workdir/indices.list"

# Strip runtime kernel addresses; collect names and owners only.
awk '$3 ~ /^__ksymtab_/ {
    name=$3; sub(/^__ksymtab_/, "", name);
    owner=$4; gsub(/[\[\]]/, "", owner);
    if (owner == "") owner="vmlinux";
    print name, owner
}' /proc/kallsyms > "$workdir/export-owners.txt"
sort -u -o "$workdir/export-owners.txt" "$workdir/export-owners.txt"
awk '$3 == "coldstart_app_tasks" || $3 == "ufs_xiaomi_comp" {
    owner=$4; gsub(/[\[\]]/, "", owner);
    if (owner == "") owner="vmlinux";
    print $3, owner
}' /proc/kallsyms > "$workdir/required-symbol-owners.txt"
sort -u -o "$workdir/required-symbol-owners.txt" "$workdir/required-symbol-owners.txt"
awk '{print $1}' /proc/modules > "$workdir/loaded-modules.txt"
sort -u -o "$workdir/loaded-modules.txt" "$workdir/loaded-modules.txt"
if [ -r /proc/config.gz ]; then
    gzip -dc /proc/config.gz > "$workdir/running-kernel.config"
fi

(cd "$workdir" && find . -type f ! -name SHA256SUMS -exec sha256sum {} \;) \
    > "$workdir/SHA256SUMS"
target=/sdcard/Download
[ -d "$target" ] || fail 'Download directory is unavailable.'
bundle="$target/umbrella-kunzite-test-baseline-$(date +%Y%m%d-%H%M%S).tar.gz"
[ ! -e "$bundle" ] || fail 'Output already exists; retry in a moment.'
tar -czf "$bundle" -C "$workdir" .
chmod 644 "$bundle"
printf '\nSaved: %s\nAttach this archive to the Umbrella conversation.\n' "$bundle"
