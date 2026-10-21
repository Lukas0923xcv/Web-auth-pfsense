<?php
/*
 * Hooks, cached privileges, username variants, trusted networks, CBOR
 * keys and revocation (security audit findings F1-F7):
 *   php tests/hooks_and_policy_test.php
 * (F0 and D1 are covered by decision-level checks at the end.)
 */

$tmp = sys_get_temp_dir();
define('WEBAUTHN_COUNTER_FILE', "$tmp/webauthn-audit-count.json");
define('WEBAUTHN_FAILURE_FILE', "$tmp/webauthn-audit-failures.json");
define('WEBAUTHN_KEY_FILE', "$tmp/webauthn-audit.key");
define('WEBAUTHN_USED_FILE', "$tmp/webauthn-audit-used.json");
define('WEBAUTHN_REVOKED_FILE', "$tmp/webauthn-audit-revoked.json");
define('WEBAUTHN_CONFIG_LOCK', "$tmp/webauthn-audit-config");
define('WEBAUTHN_NOTICE_FILE', "$tmp/webauthn-audit-notices.json");
define('WEBAUTHN_STATE_FILE', "$tmp/webauthn-audit-state.json");
define('WEBAUTHN_RUN_DIR', $tmp);
@unlink(WEBAUTHN_REVOKED_FILE);
@unlink(WEBAUTHN_NOTICE_FILE);

$GLOBALS['test_config'] = [];
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
function write_config($desc) { return $GLOBALS['test_config']; }
/* The in-memory config is the one on disk (see tests/storage_and_sessions_test.php for the snapshot case). */
function config_read_file(bool $use_backup = false, bool $use_cache = true): bool { return true; }
if (!function_exists('gettext')) {
	function gettext($s) { return $s; }
}

$repo = dirname(__DIR__);
$pkg = "$repo/src/usr/local/pkg/webauthn";
require_once("$pkg/webauthn.inc");
require_once("$pkg/hook.inc");
require_once("$pkg/xmlrpc_guard.inc");
require_once(__DIR__ . '/support/helpers.inc');

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

$public = 'https://pfsense.example.com';
$rp = 'pfsense.example.com';
$settings = [
	'enable' => 'yes', 'rp_id' => $rp, 'origins' => $public,
	'trusted_proxies' => '192.168.1.5', 'trusted_networks' => '192.168.1.0/24',
	'user_verification' => 'preferred', 'enforce' => '',
];
$tunnel = ['REMOTE_ADDR' => '192.168.1.5', 'HTTP_CF_CONNECTING_IP' => '203.0.113.9', 'HTTP_X_FORWARDED_FOR' => '203.0.113.9'];
$lan = ['REMOTE_ADDR' => '192.168.1.20'];

/* A stored passkey for "admin", as webauthn_add_credential() writes it. */
function stored_credential(string $user = 'admin'): array {
	global $rp, $public;
	$a = new FakeAuthenticator(WEBAUTHN_ALG_ES256);
	$ch = random_bytes(32);
	[$cd, $att] = $a->create($ch, $rp, $public);
	$reg = webauthn_verify_registration($cd, $att, $ch, $rp, [$public], false);
	return ['authenticator' => $a, 'record' => [
		'username' => $user, 'name' => 'key', 'id' => webauthn_b64url_encode($reg['credential_id']),
		'alg' => (string)$reg['alg'], 'publickey' => base64_encode($reg['pem']), 'rp_id' => $rp, 'created' => '0',
	]];
}

/* ------------------------------------------------------------------ */
/* F1: auth_check.inc must not trust cached page-match for sessions     */
/*     that have not passed the gate.                                  */
/* ------------------------------------------------------------------ */

$auth_check = file_get_contents(__DIR__ . '/fixtures/auth_check.inc');
$patched = webauthn_hook_apply($auth_check, 'auth_check');
check($patched !== null, 'F1: hook applies to auth_check.inc');
$hook_pos = strpos((string)$patched, WEBAUTHN_HOOK_BEGIN);
check($hook_pos > strpos((string)$patched, '$session_pagematch = session_read_single_var') &&
    $hook_pos < strpos((string)$patched, 'if (cmp_page_matches('), 'F1: hook sits between reading page-match and trusting it');

/*
 * Run the real patched auth_check.inc in a child process with stub
 * dependencies. Output: CACHED (page-match accepted) or AUTHGUI (fell
 * through to the full login path, where the gate runs).
 */
function run_auth_check(string $patched, array $config, array $session, array $server): string {
	global $repo, $tmp;
	$dir = "$tmp/webauthn-audit-authcheck";
	@mkdir($dir);
	file_put_contents("$dir/phpsessionmanager.inc", '<?php
function phpsession_begin() {} function phpsession_end($w = false) {}');
	file_put_contents("$dir/auth_func.inc", '<?php
function cmp_page_matches($page, &$matches, $fullwc = true) { return is_array($matches) && in_array("*", $matches, true); }');
	file_put_contents("$dir/config.inc", '<?php
function config_get_path($path, $default = null) { $c = $GLOBALS["cfg"]; foreach (explode("/", $path) as $p) { if (!is_array($c) || !array_key_exists($p, $c)) return $default; $c = $c[$p]; } return $c; }
if (!function_exists("gettext")) { function gettext($s) { return $s; } }');
	file_put_contents("$dir/authgui.inc", '<?php echo "AUTHGUI"; exit;');
	file_put_contents("$dir/auth_check.inc", str_replace('/usr/local/pkg/webauthn/', "$repo/src/usr/local/pkg/webauthn/", $patched));
	file_put_contents("$dir/run.php", '<?php
define("WEBAUTHN_COUNTER_FILE", ' . var_export("$tmp/webauthn-audit-count.json", true) . ');
define("WEBAUTHN_KEY_FILE", ' . var_export("$tmp/webauthn-audit.key", true) . ');
define("WEBAUTHN_USED_FILE", ' . var_export("$tmp/webauthn-audit-used.json", true) . ');
define("WEBAUTHN_REVOKED_FILE", ' . var_export("$tmp/webauthn-audit-revoked.json", true) . ');
define("WEBAUTHN_STATE_FILE", ' . var_export("$tmp/webauthn-audit-state.json", true) . ');
define("WEBAUTHN_RUN_DIR", ' . var_export($tmp, true) . ');
$GLOBALS["cfg"] = ' . var_export($config, true) . ';
$_SESSION = ' . var_export($session, true) . ';
$_SERVER = array_merge($_SERVER, ' . var_export($server + ['REQUEST_URI' => '/getstats.php'], true) . ');
require "auth_check.inc";
echo "CACHED";');
	return trim((string)shell_exec('cd ' . escapeshellarg($dir) . ' && ' . PHP_BINARY .
	    ' -d error_reporting=0 -d include_path=' . escapeshellarg($dir) . ' run.php'));
}

$cred = stored_credential();
$config = ['installedpackages' => ['webauthn' => ['config' => [$settings], 'item' => [$cred['record']]]]];
$pm = ['*'];

check(run_auth_check($patched, $config, ['Username' => 'admin', 'page-match' => $pm,
    'webauthn' => ['user' => 'admin', 'method' => 'trusted-network']], $tunnel) === 'AUTHGUI',
    'F1: LAN-exempted session reused through the tunnel does not get cached privileges');
check(run_auth_check($patched, $config, ['Username' => 'admin', 'page-match' => $pm], $tunnel) === 'AUTHGUI',
    'F1: password-only session with stale page-match falls through to authgui');
check(run_auth_check($patched, $config, ['Username' => 'admin', 'page-match' => $pm,
    'webauthn' => ['user' => 'admin', 'method' => 'webauthn', 'credential' => $cred['record']['id'],
    'time' => time(), 'sid' => '', 'rp_id' => $rp, 'uv' => false]], $tunnel) === 'CACHED',
    'F1: passkey-verified session keeps the fast path');
check(run_auth_check($patched, $config, ['Username' => 'admin', 'page-match' => $pm,
    'webauthn' => ['user' => 'admin', 'method' => 'trusted-network']], $lan) === 'CACHED',
    'F1: trusted-network request keeps the fast path');
/* Fourth review: local sessions are resolved through system/user, in auth_check.inc's lean context too. */
$local_cfg = $config + ['system' => ['user' => [['name' => 'admin', 'uid' => '0']]]];
check(run_auth_check($patched, $local_cfg, ['Username' => 'admin', 'authsource' => 'Local Database', 'page-match' => $pm,
    'webauthn' => ['user' => 'admin', 'method' => 'webauthn', 'credential' => $cred['record']['id'],
    'time' => time(), 'sid' => '', 'rp_id' => $rp, 'uv' => false]], $tunnel) === 'CACHED',
    'R4: verified local session keeps the fast path (only config.inc loaded)');
check(run_auth_check($patched, $local_cfg, ['Username' => 'ghost', 'authsource' => 'Local Database', 'page-match' => $pm,
    'webauthn' => ['user' => 'ghost', 'method' => 'trusted-network']], $lan) === 'AUTHGUI',
    'R4: local name without an account gets no cached privileges, even from a trusted network');
check(run_auth_check($patched, $local_cfg, ['Username' => 'admin', 'authsource' => 'Local Database', 'page-match' => $pm,
    'webauthn' => ['user' => 'admin', 'method' => 'webauthn', 'credential' => $cred['record']['id'],
    'time' => time() - 13 * 3600, 'sid' => '', 'rp_id' => $rp, 'uv' => false]], $tunnel) === 'AUTHGUI',
    'R4: expired verification gets no cached privileges');
$disabled = $config;
$disabled['installedpackages']['webauthn']['config'][0]['enable'] = '';
check(run_auth_check($patched, $disabled, ['Username' => 'admin', 'page-match' => $pm], $tunnel) === 'CACHED',
    'F1: second factor disabled leaves pfSense behaviour unchanged');
$removed = $config;
$removed['installedpackages']['webauthn']['item'] = [];
$removed['installedpackages']['webauthn']['config'][0]['enforce'] = 'yes';
check(run_auth_check($patched, $removed, ['Username' => 'admin', 'page-match' => $pm,
    'webauthn' => ['user' => 'admin', 'method' => 'webauthn', 'credential' => $cred['record']['id']]], $tunnel) === 'AUTHGUI',
    'F1/F7: fast path revoked once the verifying passkey is removed');

/* ------------------------------------------------------------------ */
/* F2: a username case variant must not skip the passkey step.         */
/* R5: ...and must not use another account's passkey (pfSense local    */
/*     accounts are case-sensitive: "Bob" and "bob" are two people).   */
/* ------------------------------------------------------------------ */

$GLOBALS['test_config'] = $config;
$src = webauthn_request_source($tunnel, $settings);
check(count(webauthn_get_credentials(' admin ')) === 1, 'F2: lookup trims surrounding spaces');
check(count(webauthn_get_credentials('Admin')) === 0 && count(webauthn_case_variant_credentials('Admin')) === 1,
    'R5: passkeys belong to the exact username; case variants are only detected');
check(webauthn_session_status($settings, ['Username' => 'Admin'], $src) === 'require',
    'F2: "Admin" with enforcement off must not skip the passkey step');
check(webauthn_session_status($settings, ['Username' => 'ADMIN', 'webauthn' =>
    ['user' => 'admin', 'method' => 'webauthn', 'credential' => $cred['record']['id']]], $src) === 'require',
    'R5: a session verified as "admin" does not carry over to "ADMIN"');
check(webauthn_find_credential('Admin', $cred['record']['id']) === null, 'R5: "Admin" cannot verify with the passkey of "admin"');
$ch = webauthn_new_challenge('login', 'Admin');
check(webauthn_take_challenge('login', 'admin', json_encode(['challenge' => webauthn_b64url_encode($ch)])) === null,
    'R5: challenges bind the exact username');
$GLOBALS['test_config'] = ['installedpackages' => ['webauthn' => ['config' => [$settings]]]];
$a = new FakeAuthenticator(WEBAUTHN_ALG_ES256);
$ch = random_bytes(32);
[$cd, $att] = $a->create($ch, $rp, $public);
webauthn_add_credential(' Bob ', 'k', webauthn_verify_registration($cd, $att, $ch, $rp, [$public], false), $rp);
check(webauthn_get_credentials()[0]['username'] === 'Bob', 'R5: usernames stored exactly (trimmed)');
check(webauthn_get_credentials('bob') === [] && webauthn_delete_credential(webauthn_get_credentials('Bob')[0]['id'], 'bob') === false,
    'R5: "bob" can neither use nor delete the passkey of "Bob"');

/* ------------------------------------------------------------------ */
/* F3: trusted networks need a configured cloudflared source.          */
/* ------------------------------------------------------------------ */

$base = array_merge(webauthn_default_settings(), ['enable' => 'yes', 'rp_id' => $rp]);
check(!empty(webauthn_validate_settings(array_merge($base, ['trusted_networks' => '192.168.1.0/24']))),
    'F3: trusted networks without cloudflared source refused');
check(empty(webauthn_validate_settings(array_merge($base, ['trusted_networks' => '192.168.1.0/24', 'trusted_proxies' => '192.168.1.5']))),
    'F3: trusted networks with cloudflared source accepted');
check(empty(webauthn_validate_settings($base)), 'F3: no trusted networks needs no cloudflared source');

/* ------------------------------------------------------------------ */
/* F4: every spelling of a /0 prefix is refused.                       */
/* ------------------------------------------------------------------ */

foreach (['0.0.0.0/0', '0.0.0.0/00', '10.0.0.0/000', '::/0', '::/00'] as $c) {
	check(!empty(webauthn_validate_settings(array_merge($base, ['trusted_proxies' => '192.168.1.5', 'trusted_networks' => $c]))),
	    "F4: $c refused");
}
check(empty(webauthn_validate_settings(array_merge($base, ['trusted_proxies' => '192.168.1.5', 'trusted_networks' => '10.0.0.0/08']))),
    'F4: /08 is an ordinary prefix');

/* ------------------------------------------------------------------ */
/* F5: hooks fail closed and replace older (fail-open) versions.        */
/* ------------------------------------------------------------------ */

foreach (array_keys(webauthn_hook_targets()) as $target) {
	$block = webauthn_hook_block($target);
	check(!str_contains($block, 'file_exists') && str_contains($block, 'require_once('), "F5: $target hook requires unconditionally");
}
$authgui = file_get_contents(__DIR__ . '/fixtures/authgui.inc');
$old_block = WEBAUTHN_HOOK_BEGIN . "\nif (file_exists('/usr/local/pkg/webauthn/gate.inc')) {\n\trequire_once('/usr/local/pkg/webauthn/gate.inc');\n\twebauthn_gate();\n}\n" . WEBAUTHN_HOOK_END . "\n";
$old = str_replace(webauthn_hook_block('authgui'), $old_block, webauthn_hook_apply($authgui, 'authgui'));
check(webauthn_hook_present($old) && !webauthn_hook_current($old, 'authgui'), 'F5: old fail-open hook detected as outdated');
$upgraded = webauthn_hook_apply($old, 'authgui');
check($upgraded !== null && webauthn_hook_current($upgraded, 'authgui') && !str_contains($upgraded, "file_exists('/usr/local/pkg/webauthn") &&
    substr_count($upgraded, WEBAUTHN_HOOK_BEGIN) === 1, 'F5: re-install replaces the old hook');
check($upgraded === webauthn_hook_apply($authgui, 'authgui'), 'F5: upgraded file equals a fresh install');
foreach (['authgui' => 'authgui.inc', 'auth_check' => 'auth_check.inc', 'xmlrpc' => 'xmlrpc.php'] as $target => $fixture) {
	$p = webauthn_hook_apply(file_get_contents(__DIR__ . "/fixtures/$fixture"), $target);
	$f = "$tmp/webauthn-audit-lint.php";
	file_put_contents($f, (string)$p);
	exec(PHP_BINARY . ' -l ' . escapeshellarg($f) . ' 2>&1', $out, $rc);
	check($p !== null && $rc === 0, "F5: patched $fixture parses");
	check(webauthn_hook_remove((string)$p) === file_get_contents(__DIR__ . "/fixtures/$fixture"), "F5: $fixture hook removable");
}

/* ------------------------------------------------------------------ */
/* F6: CBOR text keys never stand in for integer keys.                  */
/* ------------------------------------------------------------------ */

$m = webauthn_cbor_decode("\xa1\x61" . "1" . "\x61" . "x");   /* {"1": "x"} */
check(!isset($m[1]), 'F6: text key "1" is not integer key 1');
$enc = "\xa2" . "\x01\x02" . "\x61" . "1" . "\x03";   /* {1: 2, "1": 3} */
$m = webauthn_cbor_decode($enc);
check(($m[1] ?? null) === 2 && count($m) === 2, 'F6: integer and text keys with the same digits stay distinct');
check(webauthn_cbor_decode("\xa1\x63abc\x01") === ['abc' => 1], 'F6: ordinary text keys unchanged');
$cose = "\xa5" . "\x61" . "1" . "\x02" . "\x03\x26" . "\x20\x01" .
    "\x21\x58\x20" . str_repeat("\x01", 32) . "\x22\x58\x20" . str_repeat("\x02", 32);  /* kty given as text "1" */
$threw = false;
try {
	webauthn_cose_to_pem(webauthn_cbor_decode($cose));
} catch (WebAuthnException $e) {
	$threw = true;
}
check($threw, 'F6: COSE key with a text "1" label is rejected');

/* ------------------------------------------------------------------ */
/* F7: removing a passkey revokes the sessions it verified (gate).      */
/* ------------------------------------------------------------------ */

$state = tempnam($tmp, 'webauthn-audit-gate');
function gate_req(string $state, array $r): array {
	$out = shell_exec(PHP_BINARY . ' -d error_reporting=0 ' . escapeshellarg(__DIR__ . '/support/gate_step.php') . ' ' .
	    escapeshellarg($state) . ' ' . escapeshellarg(json_encode($r)));
	preg_match('/@@RESULT (.*)$/m', (string)$out, $mm);
	return json_decode($mm[1] ?? 'null', true) ?? [];
}
$gate_settings = array_merge($settings, ['enforce' => 'yes']);
$c = stored_credential();
$c2 = stored_credential();
file_put_contents($state, serialize([
	'config' => ['installedpackages' => ['webauthn' => ['config' => [$gate_settings], 'item' => [$c['record'], $c2['record']]]]],
	'session' => ['Username' => 'admin', 'Logged_In' => 'True'],
	'authenticator' => $c['authenticator']->toState(),
]));
gate_req($state, ['server' => $tunnel]);
$r = gate_req($state, ['server' => $tunnel, 'sign' => ['rp_id' => $rp, 'origin' => $public]]);
check(($r['webauthn']['credential'] ?? null) === $c['record']['id'], 'F7: session records the verifying passkey');
check(gate_req($state, ['server' => $tunnel])['returned'] ?? false, 'F7: verified session passes');
$st = unserialize(file_get_contents($state));
$st['config']['installedpackages']['webauthn']['item'] = [$c2['record']];
file_put_contents($state, serialize($st));
$r = gate_req($state, ['server' => $tunnel]);
check(!($r['returned'] ?? true) && ($r['webauthn'] ?? null) === null, 'F7: removing that passkey forces re-verification');

/* F2 at the gate: a case variant of the username must not skip. */
file_put_contents($state, serialize([
	'config' => ['installedpackages' => ['webauthn' => ['config' => [$settings], 'item' => [$c['record']]]]],
	'session' => ['Username' => 'Admin', 'Logged_In' => 'True'],
	'authenticator' => $c['authenticator']->toState(),
]));
check(!(gate_req($state, ['server' => $tunnel])['returned'] ?? true), 'F2: gate stops "Admin" (passkeys exist under "admin")');
unlink($state);

/* ------------------------------------------------------------------ */
/* F0 / D1 decision checks.                                             */
/* ------------------------------------------------------------------ */

check(webauthn_xmlrpc_refused(webauthn_request_source($tunnel, $settings), $settings), 'F0: XMLRPC via cloudflared refused');
$noproxy = array_merge($settings, ['trusted_proxies' => '']);
check(webauthn_xmlrpc_refused(webauthn_request_source(['REMOTE_ADDR' => '192.168.1.99', 'HTTP_X_FORWARDED_FOR' => '1.2.3.4'], $noproxy),
    $noproxy), 'F0: XMLRPC with proxy headers refused even without cloudflared source');
check(!webauthn_xmlrpc_refused(webauthn_request_source(['REMOTE_ADDR' => '192.168.1.2'], $settings), $settings), 'F0: direct HA peer allowed');
$x = webauthn_hook_apply(file_get_contents(__DIR__ . '/fixtures/xmlrpc.php'), 'xmlrpc');
check(strpos((string)$x, WEBAUTHN_HOOK_BEGIN) < strpos((string)$x, 'class pfsense_xmlrpc_server'), 'F0: guard runs before the XMLRPC server');

$GLOBALS['test_config'] = $config;
check(webauthn_session_status($settings, ['Username' => 'admin', 'webauthn' => ['user' => 'admin', 'method' => 'trusted-network']],
    webauthn_request_source($lan, $settings)) === 'skip', 'D1: trusted-network session is not "verified" (cannot add passkeys)');

echo "$count checks, $failures failed\n";
exit($failures ? 1 : 0);
