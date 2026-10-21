<?php
/*
 * End-to-end gate checks of session binding, through tests/support/gate_step.php:
 *   php tests/gate_session_test.php
 */
require_once(__DIR__ . '/support/helpers.inc');
require_once(dirname(__DIR__) . '/src/usr/local/pkg/webauthn/webauthn_lib.inc');
$rp = 'pfsense.example.com';
$settings = ['enable' => 'yes', 'rp_id' => $rp, 'origins' => "https://$rp", 'trusted_proxies' => '192.168.1.5',
    'trusted_networks' => '', 'user_verification' => 'preferred', 'enforce' => ''];
$tunnel = ['REMOTE_ADDR' => '192.168.1.5', 'HTTP_CF_CONNECTING_IP' => '203.0.113.9'];
$sign = ['rp_id' => $rp, 'origin' => "https://$rp"];

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
function req(string $state, array $r): array {
	$out = (string)shell_exec(PHP_BINARY . ' -d error_reporting=0 ' . escapeshellarg(__DIR__ . '/support/gate_step.php') . ' ' .
	    escapeshellarg($state) . ' ' . escapeshellarg(json_encode($r)));
	preg_match('/@@RESULT (.*)$/m', $out, $m);
	return (json_decode($m[1] ?? 'null', true) ?? []) + ['html' => $out];
}
function setup(string $state, array $settings, array $session = ['Username' => 'admin', 'Logged_In' => 'True']): void {
	$a = new FakeAuthenticator(WEBAUTHN_ALG_ES256);
	$ch = random_bytes(32);
	[$cd, $att] = $a->create($ch, $settings['rp_id'], 'https://' . $settings['rp_id']);
	$reg = webauthn_verify_registration($cd, $att, $ch, $settings['rp_id'], ['https://' . $settings['rp_id']], false);
	file_put_contents($state, serialize([
		'config' => ['installedpackages' => ['webauthn' => ['config' => [$settings], 'item' => [[
			'username' => 'admin', 'name' => 'key', 'id' => webauthn_b64url_encode($reg['credential_id']),
			'alg' => (string)$reg['alg'], 'publickey' => base64_encode($reg['pem']), 'rp_id' => $settings['rp_id'], 'created' => '0',
		]]]], 'system' => ['user' => [['name' => 'admin', 'uid' => '0']]]],
		'session' => $session,
		'authenticator' => $a->toState(),
	]));
}
$state = tempnam(sys_get_temp_dir(), 'r4gate');

/* 2: a password login into a verified session must pass the passkey step itself. */
setup($state, $settings);
req($state, ['server' => $tunnel]);
$r = req($state, ['server' => $tunnel, 'sign' => $sign]);
check(($r['webauthn']['method'] ?? null) === 'webauthn' && isset($r['webauthn']['sid'], $r['webauthn']['rp_id']),
    '2: verification records session ID and RP ID');
check(req($state, ['server' => $tunnel])['returned'] ?? false, '2: verified session passes');
$r = req($state, ['server' => $tunnel, 'post' => ['login' => 'Sign In', 'usernamefld' => 'admin', 'passwordfld' => 'x', 'postafterlogin' => '1']]);
check(!($r['returned'] ?? true) && str_contains($r['html'], 'webauthn-go'), '2: login POST into a verified session gets the challenge page');
check(($r['webauthn'] ?? null) === null, '2: ...and the verification is gone');

/* 2: signing in again does not reset the failure count (it would hide failed attempts). */
setup($state, $settings);
req($state, ['server' => $tunnel]);
req($state, ['server' => $tunnel, 'sign' => $sign + ['tamper' => true]]);
$r = req($state, ['server' => $tunnel, 'sign' => $sign + ['tamper' => true]]);
check($r['failures'] == 2, '2: setup: two failures');
$r = req($state, ['server' => $tunnel, 'post' => ['login' => 'Sign In', 'usernamefld' => 'admin', 'passwordfld' => 'x', 'postafterlogin' => '1']]);
check($r['failures'] == 2, '2: a login POST keeps the failure count');

/* 2: a new session ID (pfSense's password sign-in regenerates it) does not inherit the verification. */
setup($state, $settings);
req($state, ['server' => $tunnel]);
req($state, ['server' => $tunnel, 'sign' => $sign]);
check(req($state, ['server' => $tunnel])['returned'] ?? false, '2: setup: verified');
$r = req($state, ['server' => $tunnel, 'cookie' => [session_name() => 'regenerated-at-login']]);
check(!($r['returned'] ?? true), '2: same state under another session ID is not verified');

/* 1: a counter that cannot be stored fails the assertion. */
setup($state, $settings);
req($state, ['server' => $tunnel]);
$r = req($state, ['server' => $tunnel, 'sign' => $sign, 'block_counter' => true]);
check(($r['webauthn'] ?? null) === null && $r['failures'] == 1, '1: assertion fails when the counter cannot be stored');

/* 1: after a clone reported a higher counter, the real key's lower counter is refused. */
setup($state, $settings);
req($state, ['server' => $tunnel]);
$st = unserialize(file_get_contents($state));
$st['authenticator']['count'] = 49;
file_put_contents($state, serialize($st));
$r = req($state, ['server' => $tunnel, 'sign' => $sign]);
check(($r['webauthn']['method'] ?? null) === 'webauthn', '1: clone with counter 50 accepted first');
$st = unserialize(file_get_contents($state));
unset($st['session']['webauthn']);
$st['authenticator']['count'] = 9;
file_put_contents($state, serialize($st));
req($state, ['server' => $tunnel]);
$r = req($state, ['server' => $tunnel, 'sign' => $sign]);
check(($r['webauthn'] ?? null) === null && $r['failures'] == 1, '1: then counter 10 refused');

/* 5: a local sign-in name that resolves to no account is refused. */
setup($state, $settings, ['Username' => 'ghost', 'Logged_In' => 'True', 'authsource' => 'Local Database']);
$r = req($state, ['server' => $tunnel]);
check(!($r['returned'] ?? true) && str_contains($r['html'], 'no registered passkey'), '5: unresolvable local name refused');

/* 9: the login colour from user settings must be six hex digits. */
setup($state, $settings);
$r = req($state, ['server' => $tunnel, 'user_settings' => ['webgui' => ['logincss' => 'a;}x{b']]]);
check(!str_contains($r['html'], 'a;}x{b') && str_contains($r['html'], '#1e3f75'), '9: non-hex login colour ignored');
$r = req($state, ['server' => $tunnel, 'user_settings' => ['webgui' => ['logincss' => '0a0B0c']]]);
check(str_contains($r['html'], '#0a0B0c'), '9: hex login colour used');

unlink($state);
echo "$count checks, $failures failed\n";
exit($failures ? 1 : 0);
