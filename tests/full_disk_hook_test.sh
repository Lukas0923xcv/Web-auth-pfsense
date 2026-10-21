#!/bin/sh
# Mount a 64 KiB tmpfs, put the stock authgui.inc on it, fill the rest,
# and run patch_target() against it. Needs root.
set -u
d=$(mktemp -d)
mount -t tmpfs -o size=64k tmpfs "$d" || exit 2
cp "$(dirname "$0")/fixtures/authgui.inc" "$d/authgui.inc"
dd if=/dev/zero of="$d/fill" bs=1k 2>/dev/null
php "$(dirname "$0")/support/full_disk_hook.php" "$d"; rc=$?
umount "$d"; rmdir "$d"
exit $rc
