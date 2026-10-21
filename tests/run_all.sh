#!/bin/sh
# Run every off-box test: sh tests/run_all.sh
# Needs PHP 8.2+ with the openssl, sodium, intl and mbstring extensions.
# Exits non-zero if any suite fails.
#
#   COVERAGE=1          also measure line coverage (needs pcov) and fail if
#                       a required file is below the minimum (see
#                       tools/coverage_report.php)
#   REQUIRE_SHELLCHECK=1  fail if shellcheck is not installed (CI sets it)
set -u
cd "$(dirname "$0")/.." || exit 1
php=${PHP:-php}
failed=0
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

echo "== lint"
for f in src/usr/local/pkg/webauthn/*.inc src/usr/local/pkg/webauthn/hook.php src/usr/local/www/system_webauthn.php; do
	"$php" -l "$f" >/dev/null || { echo "lint failed: $f"; failed=1; }
done
echo "== code checks"
"$php" tools/function_lengths.php || failed=1
"$php" tools/unused_functions.php || failed=1
shell_scripts="install.sh uninstall.sh src/usr/local/etc/rc.d/webauthn_hook.sh tests/run_all.sh tests/full_disk_hook_test.sh tests/install_uninstall_test.sh tools/pin_install.sh tools/check_pin.sh tools/upstream_anchors.sh"
for f in $shell_scripts; do
	[ -f "$f" ] || continue
	sh -n "$f" || { echo "shell syntax error: $f"; failed=1; }
done
if command -v shellcheck >/dev/null 2>&1; then
	echo "== shellcheck"
	present=""
	for f in $shell_scripts; do
		[ -f "$f" ] && present="$present $f"
	done
	# shellcheck disable=SC2086 # the list is split on purpose
	shellcheck -s sh $present || failed=1
elif [ "${REQUIRE_SHELLCHECK:-}" = 1 ]; then
	echo "shellcheck is not installed"
	failed=1
fi

# With COVERAGE=1 every PHP process, including the ones tests start
# themselves, loads tests/support/coverage_prepend.php.
if [ "${COVERAGE:-}" = 1 ]; then
	mkdir "$work/coverage" "$work/ini"
	printf 'auto_prepend_file=%s\npcov.enabled=1\npcov.directory=%s\n' \
	    "$PWD/tests/support/coverage_prepend.php" "$PWD/src" > "$work/ini/zz-coverage.ini"
	PHP_INI_SCAN_DIR="$("$php" -r 'echo PHP_CONFIG_FILE_SCAN_DIR;'):$work/ini"
	WEBAUTHN_COVERAGE_DIR="$work/coverage"
	export PHP_INI_SCAN_DIR WEBAUTHN_COVERAGE_DIR
fi

# Each suite gets an empty temp directory, so state left by an earlier
# run (used challenges, counters) can never change the result.
for t in tests/*_test.php; do
	echo "== $t"
	dir=$(mktemp -d "$work/tmp.XXXXXX")
	TMPDIR="$dir" "$php" "$t" || { echo "FAILED: $t"; failed=1; }
done

# Tests that change the system (mount a tmpfs, write /etc/inc) need root.
for t in tests/full_disk_hook_test.sh tests/install_uninstall_test.sh; do
	[ -f "$t" ] || continue
	echo "== $t"
	if [ "$(id -u)" -ne 0 ]; then
		echo "skipped (needs root)"
		continue
	fi
	sh "$t"
	rc=$?
	if [ "$rc" -eq 2 ]; then
		echo "skipped (not possible on this machine)"
	elif [ "$rc" -ne 0 ]; then
		echo "FAILED: $t"
		failed=1
	fi
done

if [ "${COVERAGE:-}" = 1 ]; then
	unset PHP_INI_SCAN_DIR
	echo "== coverage"
	"$php" tools/coverage_report.php "$work/coverage" > "$work/coverage.md"
	rc=$?
	cat "$work/coverage.md"
	if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
		{ echo "### Line coverage (PHP $("$php" -r 'echo PHP_VERSION;'))"; echo; cat "$work/coverage.md"; } >> "$GITHUB_STEP_SUMMARY"
	fi
	[ "$rc" -eq 0 ] || { echo "Coverage below the minimum."; failed=1; }
fi

if [ "$failed" -ne 0 ]; then
	echo "Some tests FAILED."
	exit 1
fi
echo "All tests passed."
