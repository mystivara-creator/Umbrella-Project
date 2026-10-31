#!/system/bin/sh
# Read existing recovery pstore records; never mount, clear, reboot or flash.
set -eu
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || fail 'Run from a root recovery terminal.'
[ "$#" -le 1 ] || fail 'Usage: collect_recovery_pstore.sh [output-directory]'
records=/sys/fs/pstore
[ -d "$records" ] || fail 'pstore directory is unavailable in this recovery.'
found=0
for entry in "$records"/*; do
    [ -f "$entry" ] || continue
    found=1
    break
done
[ "$found" = 1 ] || fail 'No pstore records are available; nothing was changed.'
destination=${1:-/sdcard/Download}
[ -d "$destination" ] && [ -w "$destination" ] \
    || fail 'Output directory is unavailable; check recovery data decryption.'
bundle="$destination/umbrella-pstore-$(date +%Y%m%d-%H%M%S).tar.gz"
[ ! -e "$bundle" ] || fail 'Output already exists; retry in a moment.'
tar -czf "$bundle" -C "$records" .
chmod 644 "$bundle"
printf 'Saved: %s\nOriginal pstore records were retained.\n' "$bundle"
