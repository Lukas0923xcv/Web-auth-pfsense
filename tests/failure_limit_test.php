<?php
/*
 * The limit on failed passkey attempts per account and client address,
 * end to end through tests/support/gate_step.php:
 *   php tests/failure_limit_test.php
 *
 * Someone who has the password can open as many sessions as they like.
 * The limit must hold across all of them, must not let them lock out the
 * real user at another address, and when the attempt list in /conf is
 * damaged or cannot be written, no passkey is verified at all.
 */
require_once(__DIR__ . '/support/helpers.inc');
require_once(dirname(__DIR__) . '/src/usr/local/pkg/webauthn/webauthn_lib.inc');

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

/* The same files gate_step.php uses. */
$failure_file = sys_get_temp_dir() . '/webauthn-test-failures.json';
$state = tempnam(sys_get_temp_dir(), 'webauthn-limit');
const MAX_USER_FAILURES = 10;
const WINDOW = 900;

function setup(string $state, array $settings): void {
	$a = new FakeAuthenticator(WEBAUTHN_ALG_ES256);
	$ch = random_bytes(32);
	[$cd, $att] = $a->create($ch, $settings['rp_id'], 'https://pfsense.example.com');
	$reg = webauthn_verify_registration($cd, $att, $ch, $settings['rp_id'], ['https://pfsense.example.com'], false);
	file_put_contents($state, serialize([
		'config' => ['installedpackages' => ['webauthn' => [
			'config' => [$settings],
			'item' => [[
				'username' => 'admin', 'name' => 'key', 'id' => webauthn_b64url_encode($reg['credential_id']),
				'alg' => (string)$reg['alg'], 'publickey' => base64_encode($reg['pem']), 'rp_id' => $settings['rp_id'], 'created' => '0',
			]],
		]]],
		'session' => [],
		'authenticator' => $a->toState(),
	]));
	new_session($state);
}

/* A new password login with a new session cookie: nothing carries over in the session. */
function new_session(string $state): void {
	global $sid;
	$st = unserialize(file_get_contents($state));
	$st['session'] = ['Username' => 'admin', 'Logged_In' => 'True'];
	file_put_contents($state, serialize($st));
	$sid = bin2hex(random_bytes(16));
}

function req(string $state, array $r): array {
	global $sid;
	$r['cookie'] = ['PHPSESSID' => $sid];
	$out = shell_exec(PHP_BINARY . ' -d error_reporting=0 ' . escapeshellarg(__DIR__ . '/support/gate_step.php') . ' ' .
	    escapeshellarg($state) . ' ' . escapeshellarg(json_encode($r)));
	preg_match('/@@RESULT (.*)$/m', (string)$out, $m);
	$res = json_decode($m[1] ?? 'null', true) ?? [];
	$res['html'] = (string)$out;
	return $res;
}

function attempts(string $file): int {
	$data = json_decode((string)@file_get_contents($file), true);
	return is_array($data) ? (int)(array_values($data)[0]['n'] ?? 0) : 0;
}

$settings = [
	'enable' => 'yes', 'rp_id' => 'pfsense.example.com', 'origins' => 'https://pfsense.example.com',
	'trusted_proxies' => '192.168.1.5', 'trusted_networks' => '192.168.1.0/24',
	'user_verification' => 'preferred', 'enforce' => '',
];
$tunnel = ['REMOTE_ADDR' => '192.168.1.5', 'HTTP_CF_CONNECTING_IP' => '203.0.113.9'];
$sign = ['rp_id' => 'pfsense.example.com', 'origin' => 'https://pfsense.example.com'];
$locked_text = 'Too many failed passkey attempts';

/* ---- Failed attempts from many sessions add up ---- */
@unlink($failure_file);
setup($state, $settings);
$ended_early = false;
for ($i = 1; $i <= MAX_USER_FAILURES; $i++) {
	new_session($state);
	$r = req($state, ['server' => $tunnel]);
	$r = req($state, ['server' => $tunnel, 'sign' => $sign + ['tamper' => true]]);
	$ended_early = $ended_early || ($i < MAX_USER_FAILURES && $r['destroyed']);
}
check(!$ended_early, 'one failure per session stays below the per-session limit, so only the account limit applies');
check($r['destroyed'], 'the attempt that reaches the account limit ends its session');
check(attempts($failure_file) === MAX_USER_FAILURES, 'every failed attempt counted for the account and address, across ' . MAX_USER_FAILURES . ' sessions');

new_session($state);
$r = req($state, ['server' => $tunnel]);
check(!$r['returned'] && str_contains($r['html'], $locked_text) && !str_contains($r['html'], 'webauthn-go'),
    'after the limit, a new session gets the locked page and no challenge');
/* The last challenge page was never used successfully: a correct signature over it would pass if not locked. */
$r = req($state, ['server' => $tunnel, 'sign' => $sign]);
check(($r['webauthn'] ?? null) === null && str_contains($r['html'], $locked_text), 'after the limit, even the right passkey is refused');
check(attempts($failure_file) === MAX_USER_FAILURES, 'a refused attempt is not verified and adds nothing');

/* The real user at another address is not locked out (review finding F1). */
$elsewhere = ['REMOTE_ADDR' => '192.168.1.5', 'HTTP_CF_CONNECTING_IP' => '198.51.100.7'];
new_session($state);
$r = req($state, ['server' => $elsewhere]);
check(str_contains($r['html'], 'webauthn-go') && !str_contains($r['html'], $locked_text), 'another client address still gets the challenge');
$r = req($state, ['server' => $elsewhere, 'sign' => $sign]);
check(($r['webauthn']['method'] ?? null) === 'webauthn', 'the right passkey works from another address while the attacker\'s is locked');
check(attempts($failure_file) === MAX_USER_FAILURES, '...and that success does not clear the attacker\'s address');

/* The trusted network still works (the recovery path). */
new_session($state);
$r = req($state, ['server' => ['REMOTE_ADDR' => '192.168.1.20']]);
check($r['returned'] && ($r['webauthn']['method'] ?? null) === 'trusted-network', 'a trusted network still skips the passkey step while locked');

/* The lock ends WEBAUTHN_FAILURE_WINDOW after the last attempt. */
$data = json_decode(file_get_contents($failure_file), true);
foreach ($data as $k => $e) {
	$data[$k]['t'] = $e['t'] - WINDOW - 1;
}
file_put_contents($failure_file, json_encode($data));
new_session($state);
req($state, ['server' => $tunnel]);
$r = req($state, ['server' => $tunnel, 'sign' => $sign]);
check(($r['webauthn']['method'] ?? null) === 'webauthn', 'after the window the right passkey works again');
check(attempts($failure_file) === 0, 'a successful sign-in clears the count');

/* ---- A success resets the count ---- */
setup($state, $settings);
@unlink($failure_file);
req($state, ['server' => $tunnel]);
for ($i = 0; $i < 3; $i++) {
	req($state, ['server' => $tunnel, 'sign' => $sign + ['tamper' => true]]);
}
check(attempts($failure_file) === 3, 'three failures counted');
$r = req($state, ['server' => $tunnel, 'sign' => $sign]);
check(($r['webauthn']['method'] ?? null) === 'webauthn' && attempts($failure_file) === 0, 'success clears them');

/* ---- Fail closed ---- */
setup($state, $settings);
file_put_contents($failure_file, '{damaged');
$r = req($state, ['server' => $tunnel]);
check(str_contains($r['html'], $locked_text) && !str_contains($r['html'], 'webauthn-go'), 'damaged attempt list: no challenge');
$r = req($state, ['server' => $tunnel, 'sign' => $sign]);
check(($r['webauthn'] ?? null) === null, 'damaged attempt list: the right passkey is refused');
file_put_contents($failure_file, json_encode(['x' => ['n' => 'many', 't' => time(), 'u' => 'x']]));
$r = req($state, ['server' => $tunnel, 'sign' => $sign]);
check(($r['webauthn'] ?? null) === null, 'malformed entry: the right passkey is refused');

@unlink($failure_file);
setup($state, $settings);
req($state, ['server' => $tunnel]);
$r = req($state, ['server' => $tunnel, 'sign' => $sign, 'block_failures' => true]);
check(($r['webauthn'] ?? null) === null && str_contains($r['html'], $locked_text), 'attempt cannot be recorded: not verified');
$r = req($state, ['server' => $tunnel, 'sign' => $sign]);
check(($r['webauthn']['method'] ?? null) === 'webauthn', 'once it can be recorded again, the same passkey works');

/* ---- Accounts are counted separately ---- */
$data = [substr(hash('sha256', "someone-else\0203.0.113.9"), 0, 32) => ['n' => MAX_USER_FAILURES, 't' => time(),
    'u' => substr(hash('sha256', 'someone-else'), 0, 32)]];
file_put_contents($failure_file, json_encode($data));
setup($state, $settings);
req($state, ['server' => $tunnel]);
$r = req($state, ['server' => $tunnel, 'sign' => $sign]);
check(($r['webauthn']['method'] ?? null) === 'webauthn', 'another locked account does not lock this one');

/* ---- Changing addresses does not give unlimited attempts: account-wide throttle ---- */
const MAX_ACCOUNT_FAILURES = 30;
const ACCOUNT_THROTTLE = 20;
@unlink($failure_file);
setup($state, $settings);
for ($i = 1; $i <= MAX_ACCOUNT_FAILURES; $i++) {
	$from = ['REMOTE_ADDR' => '192.168.1.5', 'HTTP_CF_CONNECTING_IP' => "198.18.0.$i"];
	new_session($state);
	req($state, ['server' => $from]);
	req($state, ['server' => $from, 'sign' => $sign + ['tamper' => true]]);
}
$fresh = ['REMOTE_ADDR' => '192.168.1.5', 'HTTP_CF_CONNECTING_IP' => '198.18.1.1'];
new_session($state);
$r = req($state, ['server' => $fresh]);
check(str_contains($r['html'], $locked_text) && !str_contains($r['html'], 'webauthn-go'),
    'after ' . MAX_ACCOUNT_FAILURES . ' failures from as many addresses, a new address is throttled too');
$r = req($state, ['server' => $fresh, 'sign' => $sign]);
check(($r['webauthn'] ?? null) === null, '...and even the right passkey waits for the throttle');
$data = json_decode(file_get_contents($failure_file), true);
foreach ($data as $k => $e) {
	$data[$k]['t'] = $e['t'] - ACCOUNT_THROTTLE - 1;
}
file_put_contents($failure_file, json_encode($data));
new_session($state);
$r = req($state, ['server' => $fresh]);
check(str_contains($r['html'], 'webauthn-go'), 'after the throttle interval the account takes an attempt again');
$r = req($state, ['server' => $fresh, 'sign' => $sign]);
check(($r['webauthn']['method'] ?? null) === 'webauthn', '...and the right passkey works');

/* ---- IPv6 addresses count per /64 ---- */
@unlink($failure_file);
setup($state, $settings);
for ($i = 1; $i <= MAX_USER_FAILURES; $i++) {
	$from = ['REMOTE_ADDR' => '192.168.1.5', 'HTTP_CF_CONNECTING_IP' => sprintf('2001:db8:1:2::%x', $i)];
	new_session($state);
	req($state, ['server' => $from]);
	req($state, ['server' => $from, 'sign' => $sign + ['tamper' => true]]);
}
new_session($state);
$r = req($state, ['server' => ['REMOTE_ADDR' => '192.168.1.5', 'HTTP_CF_CONNECTING_IP' => '2001:db8:1:2:ffff::1']]);
check(str_contains($r['html'], $locked_text), 'another address in the same IPv6 /64 is locked too');
new_session($state);
$r = req($state, ['server' => ['REMOTE_ADDR' => '192.168.1.5', 'HTTP_CF_CONNECTING_IP' => '2001:db8:1:3::1']]);
check(str_contains($r['html'], 'webauthn-go'), 'an address in another /64 is not');

unlink($state);
echo "$count checks, $failures failed\n";
exit($failures ? 1 : 0);
