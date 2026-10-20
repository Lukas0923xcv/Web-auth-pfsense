<?php
/*
 * One request through webauthn_gate() with stubbed pfSense functions.
 * Usage: php gate_step.php <statefile> <json request>
 * State (config, session, authenticator key) persists in <statefile>.
 */
[$self, $stateFile, $reqJson] = $argv;
$req = json_decode($reqJson, true);
$st = file_exists($stateFile) ? unserialize(file_get_contents($stateFile)) : [];
$GLOBALS['test_config'] = $st['config'] ?? [];
$_SESSION = $st['session'] ?? [];
$GLOBALS['gate_returned'] = false;
$tmp = sys_get_temp_dir();
define('WEBAUTHN_COUNTER_FILE', "$tmp/webauthn-test-count.json");
define('WEBAUTHN_KEY_FILE', "$tmp/webauthn-test.key");
define('WEBAUTHN_USED_FILE', "$tmp/webauthn-test-used.json");

function config_get_path($path, $default = null) {
	$c = $GLOBALS['test_config'];
	foreach (explode('/', $path) as $p) {
		if (!is_array($c) || !array_key_exists($p, $c)) return $default;
		$c = $c[$p];
	}
	return $c;
}
function config_set_path($path, $value) {
	$c = &$GLOBALS['test_config'];
	foreach (explode('/', $path) as $p) {
		if (!isset($c[$p]) || !is_array($c[$p])) $c[$p] = [];
		$c = &$c[$p];
	}
	$c = $value;
}
function write_config($d) {}
function phpsession_begin() {}
function phpsession_end($w = false) {}
function phpsession_destroy() { $GLOBALS['destroyed'] = true; }
function isAjax() { return false; }
function get_user_settings($u) { return []; }
function g_get($k) { return 'pfSense'; }

require __DIR__ . '/helpers.inc';
require dirname(__DIR__) . '/src/usr/local/pkg/webauthn/gate.inc';

$_SERVER = array_merge(['REQUEST_URI' => '/firewall_rules.php', 'HTTP_HOST' => 'pfsense.example.com'], $req['server'] ?? []);
$_POST = $req['post'] ?? [];

/* Sign with the stored authenticator if asked, using a challenge from an earlier page. */
if (!empty($req['sign'])) {
	$a = FakeAuthenticator::fromState($st['authenticator']);
	$ch = webauthn_b64url_decode($st['challenges'][$req['sign']['page'] ?? count($st['challenges']) - 1]);
	[$cd, $ad, $sig] = $a->get($ch, $req['sign']['rp_id'], $req['sign']['origin']);
	if (!empty($req['sign']['tamper'])) {
		$sig[10] = chr(ord($sig[10]) ^ 1);
	}
	$st['authenticator'] = $a->toState();
	$_POST = ['webauthn_action' => 'assert', 'credential_id' => webauthn_b64url_encode($a->id),
	    'client_data' => webauthn_b64url_encode($cd), 'authenticator_data' => webauthn_b64url_encode($ad),
	    'signature' => webauthn_b64url_encode($sig)];
}

ob_start();
register_shutdown_function(function () use ($stateFile, &$st) {
	$html = ob_get_clean();
	echo $html;
	if (preg_match('/data-options="([^"]+)"/', $html, $m)) {
		$st['challenges'][] = json_decode(html_entity_decode($m[1]), true)['challenge'];
	}
	$st['config'] = $GLOBALS['test_config'];
	$st['session'] = $_SESSION;
	file_put_contents($stateFile, serialize($st));
	echo "\n@@RESULT " . json_encode([
		'returned' => $GLOBALS['gate_returned'],
		'destroyed' => !empty($GLOBALS['destroyed']),
		'webauthn' => $_SESSION['webauthn'] ?? null,
		'failures' => $_SESSION['webauthn_failures'] ?? 0,
	]) . "\n";
});

webauthn_gate();
$GLOBALS['gate_returned'] = true;
