#!/bin/sh
# Run the real install.sh and uninstall.sh against copies of pfSense's
# files, then check that uninstalling gives them back byte for byte.
#
# It writes to /etc/inc, /usr/local and /var/run like on pfSense, so it
# runs only as root, only with WEBAUTHN_SYSTEM_TEST=1 (CI sets it), and
# only where none of the pfSense paths exist yet. Exit 2 means skipped.
set -u
repo=$(cd "$(dirname "$0")/.." && pwd)

if [ "${WEBAUTHN_SYSTEM_TEST:-}" != 1 ] || [ "$(id -u)" -ne 0 ]; then
	echo "skipped (set WEBAUTHN_SYSTEM_TEST=1 and run as root, on a throw-away machine)"
	exit 2
fi
for p in /etc/inc /usr/local/bin/php /usr/local/www /usr/local/pkg/webauthn /usr/local/etc/rc.d/webauthn_hook.sh; do
	if [ -e "$p" ]; then
		echo "skipped ($p already exists: not a throw-away machine)"
		exit 2
	fi
done

php_bin=$(command -v "${PHP:-php}")
config=/var/run/webauthn-systest-config.json
created_wheel=0
# shellcheck disable=SC2317 # called through the trap
cleanup() {
	rm -rf /etc/inc /usr/local/www /usr/local/pkg/webauthn /usr/local/bin/php /usr/local/etc/rc.d/webauthn_hook.sh "$config"
	rm -f /var/run/webauthn_hook.lock /var/run/webauthn_uninstalling /var/run/webauthn_hook_failed_*
	[ "$created_wheel" = 1 ] && groupdel wheel
}
trap cleanup EXIT

# pfSense's files, from tests/fixtures.
mkdir -p /etc/inc /usr/local/www /usr/local/bin /usr/local/etc/rc.d
cp "$repo/tests/fixtures/authgui.inc" "$repo/tests/fixtures/auth_check.inc" /etc/inc/
cp "$repo/tests/fixtures/xmlrpc.php" /usr/local/www/
if ! getent group wheel >/dev/null; then
	groupadd wheel && created_wheel=1
fi
# pfSense's php finds config.inc and friends through the include path.
printf '#!/bin/sh\nexec %s -d include_path=.:/etc/inc:/usr/local/www "$@"\n' "$php_bin" > /usr/local/bin/php
chmod 0755 /usr/local/bin/php

# Minimal config.inc, util.inc, services.inc, notices.inc: the config is a
# JSON file, so the test can check what install and uninstall leave in it.
cat > /etc/inc/config.inc <<EOF
<?php
const SYSTEST_CONFIG = '$config';
function systest_load(): array { return json_decode((string)@file_get_contents(SYSTEST_CONFIG), true) ?: []; }
function config_get_path(string \$path, mixed \$default = null): mixed {
	\$c = systest_load();
	foreach (explode('/', \$path) as \$p) {
		if (!is_array(\$c) || !array_key_exists(\$p, \$c)) return \$default;
		\$c = \$c[\$p];
	}
	return \$c;
}
function config_set_path(string \$path, mixed \$value): void {
	\$all = systest_load();
	\$c = &\$all;
	foreach (explode('/', \$path) as \$p) {
		if (!isset(\$c[\$p]) || !is_array(\$c[\$p])) \$c[\$p] = [];
		\$c = &\$c[\$p];
	}
	\$c = \$value;
	file_put_contents(SYSTEST_CONFIG, json_encode(\$all));
}
function config_del_path(string \$path): void {
	\$all = systest_load();
	\$parts = explode('/', \$path);
	\$last = array_pop(\$parts);
	\$c = &\$all;
	foreach (\$parts as \$p) {
		if (!isset(\$c[\$p])) return;
		\$c = &\$c[\$p];
	}
	unset(\$c[\$last]);
	file_put_contents(SYSTEST_CONFIG, json_encode(\$all));
}
function write_config(string \$desc = ''): array { return systest_load(); }
EOF
printf '<?php\n' > /etc/inc/util.inc
cat > /etc/inc/notices.inc <<'EOF'
<?php
function file_notice(...$args) {}
EOF
cat > /etc/inc/services.inc <<'EOF'
<?php
function install_cron_job(string $command, bool $active = false, string $minute = '0'): void {
	$items = array_values(array_filter((array)config_get_path('cron/item', []), fn($i) => ($i['command'] ?? '') !== $command));
	if ($active) {
		$items[] = ['minute' => $minute, 'hour' => '*', 'mday' => '*', 'month' => '*', 'wday' => '*', 'who' => 'root', 'command' => $command];
	}
	config_set_path('cron/item', $items);
}
EOF
echo '{"system":{"earlyshellcmd":["/usr/local/bin/other-early-command"]},"cron":{"item":[]}}' > "$config"

failed=0
# check <exit status of the test just run> <description>
check() {
	if [ "$1" -eq 0 ]; then
		echo "ok: $2"
	else
		echo "FAIL: $2"
		failed=1
	fi
}

out=$(sh "$repo/install.sh" 2>&1)
rc=$?
echo "$out" | sed 's/^/    install: /'
[ "$rc" -eq 0 ]
check $? 'install.sh succeeds'
echo "$out" | grep -q "^Installed version $(cat "$repo/src/usr/local/pkg/webauthn/VERSION")"
check $? 'install.sh reports the installed version'
/usr/local/bin/php -f /usr/local/pkg/webauthn/hook.php status >/dev/null
check $? 'hook.php status: every hook, the cron job and the boot command present'
! cmp -s /etc/inc/authgui.inc "$repo/tests/fixtures/authgui.inc"
check $? 'authgui.inc is patched'
grep -q "webauthn_gate();" /etc/inc/authgui.inc && grep -q "webauthn_cached_privileges_allowed" /etc/inc/auth_check.inc && grep -q "webauthn_xmlrpc_guard();" /usr/local/www/xmlrpc.php
check $? 'all three hooks are in place'
[ "$(stat -c %a /usr/local/pkg/webauthn/hook.php)" = 755 ] && [ "$(stat -c %U:%G /usr/local/pkg/webauthn/webauthn.inc)" = root:wheel ]
check $? 'files are installed root:wheel with the right modes'

# Installing twice (an update) changes nothing more.
cp /etc/inc/authgui.inc /var/run/webauthn-systest-authgui.once
sh "$repo/install.sh" >/dev/null 2>&1
cmp -s /etc/inc/authgui.inc /var/run/webauthn-systest-authgui.once
check $? 'installing again leaves the patched files as they are'
rm -f /var/run/webauthn-systest-authgui.once

out=$(sh "$repo/uninstall.sh" 2>&1)
rc=$?
echo "$out" | sed 's/^/    uninstall: /'
[ "$rc" -eq 0 ]
check $? 'uninstall.sh succeeds'
cmp -s /etc/inc/authgui.inc "$repo/tests/fixtures/authgui.inc"
check $? 'authgui.inc byte-identical to the original after uninstall'
cmp -s /etc/inc/auth_check.inc "$repo/tests/fixtures/auth_check.inc"
check $? 'auth_check.inc byte-identical to the original after uninstall'
cmp -s /usr/local/www/xmlrpc.php "$repo/tests/fixtures/xmlrpc.php"
check $? 'xmlrpc.php byte-identical to the original after uninstall'
[ ! -e /usr/local/pkg/webauthn ] && [ ! -e /usr/local/www/system_webauthn.php ] && [ ! -e /usr/local/www/webauthn ] && [ ! -e /usr/local/etc/rc.d/webauthn_hook.sh ]
check $? 'package files removed'
"$php_bin" -r "\$c = json_decode(file_get_contents(\"$config\"), true); exit((\$c[\"cron\"][\"item\"] ?? []) === [] && (\$c[\"system\"][\"earlyshellcmd\"] ?? null) === [\"/usr/local/bin/other-early-command\"] && (\$c[\"installedpackages\"][\"menu\"] ?? []) === [] ? 0 : 1);"
check $? 'cron job, boot command and menu entry removed; other boot commands kept'
[ -z "$(find /etc/inc /usr/local/www -name "*webauthn*")" ]
check $? 'no backups or temp files left next to the pfSense files'

[ "$failed" -eq 0 ] && echo "install/uninstall: all checks passed"
exit "$failed"
