<?php
/*
 * End-to-end tests of webauthn_gate(): php tests/gate_test.php
 * Each request runs in its own process because the gate exits.
 */
require_once(__DIR__ . '/helpers.inc');
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

$state = tempnam(sys_get_temp_dir(), 'webauthn-gate');

function setup(string $state, array $settings): void {
	$a = new FakeAuthenticator(WEBAUTHN_ALG_ES256);
	$ch = random_bytes(32);
	[$cd, $att] = $a->create($ch, $settings['rp_id'], 'https://pfsense.example.com');
	$reg = webauthn_verify_registration($cd, $att, $ch, $settings['rp_id'], ['https://pfsense.example.com'], false);
	$config = ['installedpackages' => ['webauthn' => [
		'config' => [$settings],
		'item' => [[
			'username' => 'admin', 'name' => 'key', 'id' => webauthn_b64url_encode($reg['credential_id']),
			'alg' => (string)$reg['alg'], 'publickey' => base64_encode($reg['pem']), 'rp_id' => $settings['rp_id'], 'created' => '0',
		]],
	]]];
	file_put_contents($state, serialize([
		'config' => $config,
		'session' => ['Username' => 'admin', 'Logged_In' => 'True'],
		'authenticator' => $a->toState(),
	]));
}

function req(string $state, array $r): array {
	$out = shell_exec(PHP_BINARY . ' -d error_reporting=0 ' . escapeshellarg(__DIR__ . '/gate_step.php') . ' ' .
	    escapeshellarg($state) . ' ' . escapeshellarg(json_encode($r)));
	preg_match('/@@RESULT (.*)$/m', $out, $m);
	$res = json_decode($m[1] ?? 'null', true) ?? [];
	$res['html'] = $out;
	return $res;
}

$settings = [
	'enable' => 'yes', 'rp_id' => 'example.com',
	'origins' => "https://pfsense.example.com\nhttps://pfsense.lan.example.com",
	'trusted_proxies' => '192.168.1.5', 'trusted_networks' => '192.168.1.0/24',
	'user_verification' => 'preferred', 'enforce' => '',
];
$tunnel = ['REMOTE_ADDR' => '192.168.1.5', 'HTTP_CF_CONNECTING_IP' => '203.0.113.9'];
$sign = ['rp_id' => 'example.com', 'origin' => 'https://pfsense.example.com'];

/* Tunnel: challenge shown, then a valid assertion passes. */
setup($state, $settings);
$r = req($state, ['server' => $tunnel]);
check(!$r['returned'] && str_contains($r['html'], 'webauthn-go'), 'tunnel request gets challenge page');
$r = req($state, ['server' => $tunnel, 'sign' => $sign]);
check(($r['webauthn']['method'] ?? null) === 'webauthn', 'valid passkey accepted');
$r = req($state, ['server' => $tunnel]);
check($r['returned'], 'verified session passes through');

/* A reload (or a password manager fetching the page) does not invalidate
 * the challenge already in use, and a signed challenge cannot be replayed. */
setup($state, $settings);
req($state, ['server' => $tunnel]);
req($state, ['server' => $tunnel]);
$r = req($state, ['server' => $tunnel, 'sign' => $sign + ['page' => 0]]);
check(($r['webauthn']['method'] ?? null) === 'webauthn', 'challenge from first of two page loads accepted');
$st = unserialize(file_get_contents($state));
unset($st['session']['webauthn']);
file_put_contents($state, serialize($st));
$r = req($state, ['server' => $tunnel, 'sign' => $sign + ['page' => 0]]);
check(($r['webauthn'] ?? null) === null && $r['failures'] == 1, 'replayed challenge refused');

/* LAN hostname under parent RP ID works with the same passkey. */
setup($state, $settings);
req($state, ['server' => ['REMOTE_ADDR' => '10.9.9.9', 'HTTP_HOST' => 'pfsense.lan.example.com']]);
$r = req($state, ['server' => ['REMOTE_ADDR' => '10.9.9.9'], 'sign' => ['rp_id' => 'example.com', 'origin' => 'https://pfsense.lan.example.com']]);
check(($r['webauthn']['method'] ?? null) === 'webauthn', 'LAN hostname accepted under parent RP ID');

/* Wrong origin is refused even though pfSense would see HTTP locally. */
setup($state, $settings);
req($state, ['server' => $tunnel]);
$r = req($state, ['server' => $tunnel, 'sign' => ['rp_id' => 'example.com', 'origin' => 'https://evil.example']]);
check(($r['webauthn'] ?? null) === null && $r['failures'] == 1, 'foreign origin refused');

/* Five failures end the session; nothing is logged in sshguard's format. */
setup($state, $settings);
req($state, ['server' => $tunnel]);
for ($i = 0; $i < 5; $i++) {
	$r = req($state, ['server' => $tunnel, 'sign' => $sign + ['tamper' => true]]);
}
check($r['destroyed'], 'session destroyed after repeated failures');

/* Trusted LAN by IP skips WebAuthn; tunnel via LAN cloudflared does not. */
setup($state, $settings);
$r = req($state, ['server' => ['REMOTE_ADDR' => '192.168.1.20', 'HTTP_HOST' => '192.168.1.1']]);
check($r['returned'] && ($r['webauthn']['method'] ?? null) === 'trusted-network', 'LAN by IP skips');
$r = req($state, ['server' => $tunnel]);
check(!$r['returned'], 'same session via tunnel must verify');

/* Host rewritten by cloudflared: the challenge is still offered; the
 * browser checks its own origin against the list sent with it. */
setup($state, $settings);
$r = req($state, ['server' => $tunnel + ['HTTP_HOST' => '127.0.0.1']]);
check(!$r['returned'] && str_contains($r['html'], 'webauthn-go') && str_contains($r['html'], 'webauthn-wronghost') &&
    str_contains($r['html'], htmlspecialchars('"origins":["https:\\/\\/pfsense.example.com"')), 'challenge offered despite rewritten Host');

/* Enforcement without a passkey denies. */
$s2 = $settings;
$s2['enforce'] = 'yes';
setup($state, $s2);
$st = unserialize(file_get_contents($state));
$st['session']['Username'] = 'bob';
file_put_contents($state, serialize($st));
$r = req($state, ['server' => $tunnel]);
check(!$r['returned'] && str_contains($r['html'], 'no registered passkey'), 'enforced user without passkey denied');

/* Disabled: pass. */
$s3 = $settings;
$s3['enable'] = '';
setup($state, $s3);
check(req($state, ['server' => $tunnel])['returned'], 'disabled gate passes');

unlink($state);
echo "$count checks, $failures failed\n";
exit($failures ? 1 : 0);
