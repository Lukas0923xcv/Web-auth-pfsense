<?php
/*
 * Shared stub for tests that run several processes: the config lives in
 * a file ($D/config.ser) like config.xml; each process has its own
 * in-memory copy, loaded when it starts, as a pfSense request does.
 */
$D = getenv('WEBAUTHN_RACE_DIR');
define('WEBAUTHN_COUNTER_FILE', "$D/count.json");
define('WEBAUTHN_FAILURE_FILE', "$D/failures.json");
define('WEBAUTHN_KEY_FILE', "$D/key");
define('WEBAUTHN_USED_FILE', "$D/used.json");
define('WEBAUTHN_REVOKED_FILE', "$D/revoked.json");
define('WEBAUTHN_CONFIG_LOCK', "$D/config");
define('WEBAUTHN_NOTICE_FILE', "$D/notices.json");
define('WEBAUTHN_STATE_FILE', "$D/state.json");
define('WEBAUTHN_RUN_DIR', "$D");
define('RACE_DISK', "$D/config.ser");
$GLOBALS['test_config'] = file_exists(RACE_DISK) ? unserialize(file_get_contents(RACE_DISK)) : [];
function config_get_path($path, $default = null) {
	$c = $GLOBALS['test_config'];
	foreach (explode('/', $path) as $p) {
		if (!is_array($c) || !array_key_exists($p, $c)) {
			return $default;
		}
		$c = $c[$p];
	}
	return $c;
}
function config_set_path($path, $value) {
	$c = &$GLOBALS['test_config'];
	foreach (explode('/', $path) as $p) {
		if (!isset($c[$p]) || !is_array($c[$p])) {
			$c[$p] = [];
		}
		$c = &$c[$p];
	}
	$c = $value;
}
function write_config($desc) {
	usleep(20000);   /* writing config.xml takes a while */
	file_put_contents(RACE_DISK, serialize($GLOBALS['test_config']));
	return $GLOBALS['test_config'];
}
function config_read_file(bool $use_backup = false, bool $use_cache = true): bool {
	$GLOBALS['test_config'] = unserialize(file_get_contents(RACE_DISK));
	return true;
}
function file_notice($id, $notice, $category = 'General', $url = '', $priority = 1, $local_only = false) {
	file_put_contents(getenv('WEBAUTHN_RACE_DIR') . '/notices.log', $notice . "\n", FILE_APPEND);
}
function phpsession_begin() {}
function phpsession_end($w = false) {}
if (!function_exists('gettext')) {
	function gettext($s) { return $s; }
}
require_once(dirname(__DIR__, 2) . '/src/usr/local/pkg/webauthn/gate.inc');
require_once(__DIR__ . '/helpers.inc');
