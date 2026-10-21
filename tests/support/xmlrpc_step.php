<?php
/*
 * One request through webauthn_xmlrpc_guard(), as the xmlrpc.php hook runs
 * it. Usage: php xmlrpc_step.php <json settings> <json $_SERVER>
 * Prints "PASSED" if the guard let the request through (it exits otherwise).
 */
[, $settingsJson, $serverJson] = $argv;
$GLOBALS['test_config'] = ['installedpackages' => ['webauthn' => ['config' => [json_decode($settingsJson, true)]]]];
function config_get_path($path, $default = null) {
	$c = $GLOBALS['test_config'];
	foreach (explode('/', $path) as $p) {
		if (!is_array($c) || !array_key_exists($p, $c)) return $default;
		$c = $c[$p];
	}
	return $c;
}
if (!function_exists('gettext')) {
	function gettext($s) { return $s; }
}
require dirname(__DIR__, 2) . '/src/usr/local/pkg/webauthn/xmlrpc_guard.inc';
$_SERVER = json_decode($serverJson, true);
webauthn_xmlrpc_guard();
echo "PASSED\n";
