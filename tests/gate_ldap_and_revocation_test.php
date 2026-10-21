<?php
/*
 * End-to-end gate checks, through tests/support/gate_step.php:
 *   php tests/gate_ldap_and_revocation_test.php
 * R1: an LDAP spelling of a username with passkeys must not pass the gate.
 * R2: a session whose (last) passkey was removed is signed out.
 */
require_once(__DIR__ . '/support/helpers.inc');
require_once(dirname(__DIR__) . '/src/usr/local/pkg/webauthn/webauthn_lib.inc');
$rp = 'pfsense.example.com';
$settings = ['enable' => 'yes', 'rp_id' => $rp, 'origins' => "https://$rp", 'trusted_proxies' => '192.168.1.5',
    'trusted_networks' => '', 'user_verification' => 'preferred', 'enforce' => ''];
$tunnel = ['REMOTE_ADDR' => '192.168.1.5', 'HTTP_CF_CONNECTING_IP' => '203.0.113.9'];
$a = new FakeAuthenticator(WEBAUTHN_ALG_ES256);
$ch = random_bytes(32);
[$cd, $att] = $a->create($ch, $rp, "https://$rp");
$reg = webauthn_verify_registration($cd, $att, $ch, $rp, ["https://$rp"], false);
$record = ['username' => 'admin', 'name' => 'key', 'id' => webauthn_b64url_encode($reg['credential_id']),
    'alg' => (string)$reg['alg'], 'publickey' => base64_encode($reg['pem']), 'rp_id' => $rp, 'created' => '0'];

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
function gate(array $config, array $session, array $server): array {
	$state = tempnam(sys_get_temp_dir(), 'r3gate');
	file_put_contents($state, serialize(['config' => $config, 'session' => $session]));
	$out = (string)shell_exec(PHP_BINARY . ' -d error_reporting=0 ' . escapeshellarg(__DIR__ . '/support/gate_step.php') . ' ' .
	    escapeshellarg($state) . ' ' . escapeshellarg(json_encode(['server' => $server])));
	unlink($state);
	preg_match('/@@RESULT (.*)$/m', $out, $m);
	return (json_decode($m[1] ?? 'null', true) ?? []) + ['html' => $out];
}

$config = ['installedpackages' => ['webauthn' => ['config' => [$settings], 'item' => [$record]]]];
$ldap = ['Logged_In' => 'True', 'remoteauth' => true, 'authsource' => 'LDAP/corp'];
foreach (['admin', 'admin@x', 'ADMIN\\corp'] as $user) {
	$r = gate($config, ['Username' => $user] + $ldap, $tunnel);
	check(!($r['returned'] ?? true), "R1 '$user' via the tunnel does not pass the gate without a passkey");
}
$r = gate($config, ['Username' => 'admin@x'] + $ldap, $tunnel);
check(str_contains($r['html'], 'another spelling'), 'R1 the variant gets the "registered spelling" page');

/* R2: last passkey removed, Enforce off: the session it verified is signed out. */
$empty = ['installedpackages' => ['webauthn' => ['config' => [$settings], 'item' => []]]];
$r = gate($empty, ['Username' => 'admin', 'webauthn' => ['user' => 'admin', 'method' => 'webauthn', 'credential' => $record['id']]] + $ldap, $tunnel);
check(!($r['returned'] ?? true) && ($r['destroyed'] ?? false), 'R2 session verified with a removed last passkey is destroyed');

echo "$count checks, $failures failed\n";
exit($failures ? 1 : 0);
