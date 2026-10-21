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
define('WEBAUTHN_FAILURE_FILE', "$tmp/webauthn-test-failures.json");
define('WEBAUTHN_KEY_FILE', "$tmp/webauthn-test.key");
define('WEBAUTHN_USED_FILE', "$tmp/webauthn-test-used.json");
define('WEBAUTHN_REVOKED_FILE', "$tmp/webauthn-test-revoked.json");
define('WEBAUTHN_CONFIG_LOCK', "$tmp/webauthn-test-config");
define('WEBAUTHN_NOTICE_FILE', "$tmp/webauthn-test-notices.json");
define('WEBAUTHN_STATE_FILE', "$tmp/webauthn-test-state.json");
define('WEBAUTHN_RUN_DIR', $tmp);

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
function write_config($d) { return $GLOBALS['test_config']; }
/* The in-memory config is the one on disk (see tests/storage_and_sessions_test.php for the snapshot case). */
function config_read_file(bool $use_backup = false, bool $use_cache = true): bool { return true; }
function phpsession_begin() {}
function phpsession_end($w = false) {}
function phpsession_destroy() { $GLOBALS['destroyed'] = true; }
function isAjax() { return false; }
function get_user_settings($u) { return $GLOBALS['req_user_settings'] ?? []; }
function g_get($k) { return 'pfSense'; }

require __DIR__ . '/helpers.inc';
require dirname(__DIR__, 2) . '/src/usr/local/pkg/webauthn/gate.inc';

$_SERVER = array_merge(['REQUEST_URI' => '/firewall_rules.php', 'HTTP_HOST' => 'pfsense.example.com'], $req['server'] ?? []);
$_POST = $req['post'] ?? [];
$_COOKIE = $req['cookie'] ?? [];
$GLOBALS['req_user_settings'] = $req['user_settings'] ?? [];
if (!empty($req['block_counter'])) {
	/* A directory where the counter's temp file would go: the counter cannot be written. */
	@mkdir(WEBAUTHN_COUNTER_FILE . '.' . getmypid() . '.tmp');
}
if (!empty($req['block_failures'])) {
	/* Same for the per-account attempt list. */
	@mkdir(WEBAUTHN_FAILURE_FILE . '.' . getmypid() . '.tmp');
}

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
	if (isset($req['sign']['user_handle'])) {
		/* 'own', or a base64url user handle. */
		$_POST['user_handle'] = $req['sign']['user_handle'] === 'own'
		    ? webauthn_b64url_encode(hash('sha256', 'pfsense-webauthn:' . ($_SESSION['Username'] ?? ''), true)) : $req['sign']['user_handle'];
	}
}

ob_start();
register_shutdown_function(function () use ($stateFile, &$st) {
	@rmdir(WEBAUTHN_COUNTER_FILE . '.' . getmypid() . '.tmp');
	@rmdir(WEBAUTHN_FAILURE_FILE . '.' . getmypid() . '.tmp');
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
