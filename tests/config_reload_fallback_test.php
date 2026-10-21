<?php
/*
 * Finding 3 on pfSense versions without config_read_file() (2.7.x):
 *   php tests/config_reload_fallback_test.php
 * The config is reloaded with pfSense's parse_xml_config(); if that
 * fails, the change is not made (fail closed).
 */
$tmp = sys_get_temp_dir();
define('WEBAUTHN_COUNTER_FILE', "$tmp/webauthn-r4f-count.json");
define('WEBAUTHN_FAILURE_FILE', "$tmp/webauthn-r4f-failures.json");
define('WEBAUTHN_KEY_FILE', "$tmp/webauthn-r4f.key");
define('WEBAUTHN_USED_FILE', "$tmp/webauthn-r4f-used.json");
define('WEBAUTHN_REVOKED_FILE', "$tmp/webauthn-r4f-revoked.json");
define('WEBAUTHN_CONFIG_LOCK', "$tmp/webauthn-r4f-config");
define('WEBAUTHN_NOTICE_FILE', "$tmp/webauthn-r4f-notices.json");
define('WEBAUTHN_STATE_FILE', "$tmp/webauthn-r4f-state.json");
define('WEBAUTHN_RUN_DIR', $tmp);
@unlink(WEBAUTHN_REVOKED_FILE);

/* As in pfSense: the config lives in $GLOBALS['config']. */
function config_get_path($path, $default = null) {
	$c = $GLOBALS['config'];
	foreach (explode('/', $path) as $p) {
		if (!is_array($c) || !array_key_exists($p, $c)) {
			return $default;
		}
		$c = $c[$p];
	}
	return $c;
}
function config_set_path($path, $value) {
	$c = &$GLOBALS['config'];
	foreach (explode('/', $path) as $p) {
		if (!isset($c[$p]) || !is_array($c[$p])) {
			$c[$p] = [];
		}
		$c = &$c[$p];
	}
	$c = $value;
}
function write_config($desc) {
	$GLOBALS['disk'] = $GLOBALS['config'];
	return $GLOBALS['config'];
}
function g_get($k) {
	return ['conf_path' => '/cf/conf', 'xml_rootobj' => 'pfsense'][$k];
}
function parse_xml_config($file, $root) {
	$GLOBALS['parsed'][] = [$file, $root];
	return $GLOBALS['parse_result'];
}
if (!function_exists('gettext')) {
	function gettext($s) { return $s; }
}
require_once(dirname(__DIR__) . '/src/usr/local/pkg/webauthn/webauthn.inc');

$failures = 0;
$count = 0;
function check($cond, $name) {
	global $failures, $count;
	$count++;
	if (!$cond) {
		$failures++;
		echo "FAIL: $name\n";
	}
}

check(!function_exists('config_read_file'), 'setup: no config_read_file()');
$GLOBALS['config'] = ['stale' => true];
$GLOBALS['parse_result'] = ['installedpackages' => ['webauthn' => ['item' => []]], 'fresh' => true];
check(webauthn_save_settings(['enable' => '']) && !empty($GLOBALS['disk']['fresh']) && empty($GLOBALS['disk']['stale']),
    '3: change made on the config parsed from disk');
check(($GLOBALS['parsed'][0] ?? null) === ['/cf/conf/config.xml', ['pfsense']], '3: config.xml parsed with pfSense\'s root tag');
$GLOBALS['disk'] = null;
$GLOBALS['parse_result'] = -1;
check(!webauthn_save_settings(['enable' => 'yes']) && $GLOBALS['disk'] === null, '3: unreadable config.xml: change not made');

foreach ([WEBAUTHN_COUNTER_FILE, WEBAUTHN_REVOKED_FILE] as $f) {
	@unlink($f);
	@unlink("$f.lock");
}
@unlink(WEBAUTHN_CONFIG_LOCK . '.lock');
echo "$count checks, $failures failed\n";
exit($failures ? 1 : 0);
