#!/bin/sh
# Run every off-box test: sh tests/run_all.sh
# Needs PHP 8.1+ with the openssl, sodium, intl and mbstring extensions.
# Exits non-zero if any suite fails.
set -u
cd "$(dirname "$0")/.."
php=${PHP:-php}
failed=0

echo "== lint"
for f in src/usr/local/pkg/webauthn/*.inc src/usr/local/pkg/webauthn/hook.php src/usr/local/www/system_webauthn.php; do
	"$php" -l "$f" >/dev/null || { echo "lint failed: $f"; failed=1; }
done
for f in install.sh uninstall.sh src/usr/local/etc/rc.d/webauthn_hook.sh; do
	sh -n "$f" || { echo "shell syntax error: $f"; failed=1; }
done

for t in \
	tests/run.php \
	tests/audit_test.php \
	tests/gate_test.php \
	tests/review3/review3_test.php \
	tests/review3/gate_ldap_variant.php \
	tests/review3/fuzz_parsers.php \
	tests/review4/review4_test.php \
	tests/review4/review4b_test.php \
	tests/review4/gate_review4.php \
	tests/review4/reload_fallback.php
do
	echo "== $t"
	"$php" "$t" || { echo "FAILED: $t"; failed=1; }
done

# The full-disk test mounts a tiny tmpfs, so it needs root.
echo "== tests/review3/hook_enospc.sh"
if [ "$(id -u)" -eq 0 ]; then
	sh tests/review3/hook_enospc.sh
	rc=$?
	if [ "$rc" -eq 2 ]; then
		echo "skipped (cannot mount a tmpfs here)"
	elif [ "$rc" -ne 0 ]; then
		echo "FAILED: tests/review3/hook_enospc.sh"
		failed=1
	fi
else
	echo "skipped (needs root)"
fi

if [ "$failed" -ne 0 ]; then
	echo "Some tests FAILED."
	exit 1
fi
echo "All tests passed."
