<?php
/*
 * Regression tests for the third security review (REVIEW3.md):
 *   php tests/review3/review3_test.php
 */
$tmp = sys_get_temp_dir();
define('WEBAUTHN_COUNTER_FILE', "$tmp/webauthn-r3-count.json");
define('WEBAUTHN_KEY_FILE', "$tmp/webauthn-r3.key");
define('WEBAUTHN_USED_FILE', "$tmp/webauthn-r3-used.json");
@unlink(WEBAUTHN_USED_FILE);

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
function write_config($desc) {}
function phpsession_begin() {}
function phpsession_end($w = false) {}
if (!function_exists('gettext')) {
	function gettext($s) { return $s; }
}

$repo = dirname(__DIR__, 2);
$pkg = "$repo/src/usr/local/pkg/webauthn";
require_once("$pkg/gate.inc");
require_once("$pkg/xmlrpc_guard.inc");
require_once("$repo/tests/helpers.inc");

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

$rp = 'pfsense.example.com';
$settings = array_merge(webauthn_default_settings(), [
	'enable' => 'yes', 'rp_id' => $rp, 'origins' => "https://$rp",
	'trusted_proxies' => '192.168.1.5', 'trusted_networks' => '192.168.1.0/24',
	'user_verification' => 'preferred', 'enforce' => '',
]);
$tunnel = webauthn_request_source(['REMOTE_ADDR' => '192.168.1.5', 'HTTP_CF_CONNECTING_IP' => '203.0.113.9'], $settings);
$lan_trusted = webauthn_request_source(['REMOTE_ADDR' => '192.168.1.20'], $settings);
$lan_other = webauthn_request_source(['REMOTE_ADDR' => '10.0.0.66'], $settings);
$ldap = ['remoteauth' => true, 'authsource' => 'LDAP/corp'];
$local = ['remoteauth' => true, 'authsource' => 'Local Database'];

function reset_config(array $settings, array $users): void {
	$GLOBALS['test_config'] = ['installedpackages' => ['webauthn' => ['config' => [$settings], 'item' => []]]];
	foreach ($users as $u) {
		$a = new FakeAuthenticator(WEBAUTHN_ALG_ES256);
		$ch = random_bytes(32);
		[$cd, $att] = $a->create($ch, $settings['rp_id'], 'https://' . $settings['rp_id']);
		$reg = webauthn_verify_registration($cd, $att, $ch, $settings['rp_id'], ['https://' . $settings['rp_id']], false);
		webauthn_add_credential($u, 'key', $reg, $settings['rp_id']);
	}
}

/*
 * R1. pfSense's ldap_backed() and ldap_get_groups() (auth.inc) cut the
 * username at '@' (unless ldap_nostrip_at) and at '\', and directories
 * match names ignoring case, width and extra spaces. "admin@x" signs in
 * as, and gets the groups of, LDAP user admin, while session Username
 * stays "admin@x". It must not skip the passkey step of "admin".
 */
reset_config($settings, ['admin']);
foreach (['admin@x', 'admin\\x', "admin\u{00A0}", "\u{FF41}dmin", 'ADMIN@corp', 'Admin',
    "ad\u{00AD}min", "ad\u{200B}min", "admin\u{FE0F}", 'CORP\\admin', 'corp/admin', 'CORP\\Admin@corp'] as $variant) {
	$st = webauthn_session_status($settings, ['Username' => $variant] + $ldap, $tunnel);
	check($st === 'require', 'R1 LDAP/RADIUS spelling ' . json_encode($variant) . " of 'admin' must not skip the passkey step (got $st)");
}
check(webauthn_session_status($settings, ['Username' => 'carol'] + $ldap, $tunnel) === 'skip',
    'R1 an unrelated LDAP user without passkeys still skips while Enforce is off');
/* Two users of one domain are not spellings of each other. */
reset_config($settings, ['alice@corp', 'CORP\\alice']);
foreach (['bob@corp', 'CORP\\bob', 'corp'] as $other) {
	$st = webauthn_session_status($settings, ['Username' => $other] + $ldap, $tunnel);
	check($st === 'skip', "R1 '$other' is not taken for alice (got $st)");
}
check(webauthn_session_status($settings, ['Username' => 'alice'] + $ldap, $tunnel) === 'require', "R1 'alice' is a spelling of 'alice@corp'");
reset_config($settings, ['admin']);
check(webauthn_session_status($settings, ['Username' => 'admin'] + $ldap, $tunnel) === 'require', 'R1 the exact name still requires');

/*
 * R10. Local accounts are exact and case-sensitive: local "Bob" is not
 * locked out because a different local user "bob" has a passkey.
 */
reset_config($settings, ['bob']);
check(webauthn_session_status($settings, ['Username' => 'Bob'] + $local, $tunnel) === 'skip',
    'R10 local "Bob" is a different account from "bob" and is not refused');
check(webauthn_session_status($settings, ['Username' => 'Bob'] + $ldap, $tunnel) === 'require',
    'R10 LDAP "Bob" is the same person as "bob" and must use the passkey');

/*
 * R2. "Removing a passkey ends the sessions it verified" (README), also
 * when it was the user's last passkey and Enforce is off.
 */
reset_config($settings, ['admin']);
$cred = webauthn_get_credentials('admin')[0]['id'];
$session = ['Username' => 'admin', 'webauthn' => ['user' => 'admin', 'method' => 'webauthn', 'credential' => $cred]];
check(webauthn_session_status($settings, $session, $tunnel) === 'verified', 'R2 setup: session verified');
webauthn_delete_credential($cred, null);
$st = webauthn_session_status($settings, $session, $tunnel);
check($st === 'revoked', "R2 session verified with a removed (last) passkey is revoked (got $st)");
check(webauthn_session_status($settings, ['Username' => 'admin', 'webauthn' => ['user' => 'other', 'method' => 'webauthn',
    'credential' => $cred]], $tunnel) === 'skip', 'R2 state left by another user after a re-login is ignored, not revoked');

/*
 * R4. Once an account has a passkey, adding another needs a session that
 * signed in with one, also for other spellings of a remote account.
 */
reset_config($settings, ['admin']);
foreach (['Admin', 'admin@x', 'admin'] as $variant) {
	check(!webauthn_may_register($settings, ['Username' => $variant] + $ldap, $lan_trusted),
	    "R4 '$variant' on a trusted network may not enrol a passkey without one while 'admin' has passkeys");
}
check(webauthn_may_register($settings, ['Username' => 'carol'] + $ldap, $lan_trusted), 'R4 a user without passkeys may enrol the first one');
check(webauthn_may_register($settings, ['Username' => 'Admin'] + $local, $lan_trusted), 'R4 a distinct local user "Admin" may enrol its own');
$cred = webauthn_get_credentials('admin')[0]['id'];
check(webauthn_may_register($settings, ['Username' => 'admin', 'webauthn' => ['user' => 'admin', 'method' => 'webauthn',
    'credential' => $cred]] + $ldap, $tunnel), 'R4 a passkey-verified session may add another');

/*
 * R5. While WebAuthn is enabled, XMLRPC (password only, exec_shell) is
 * accepted only from XMLRPC peers and trusted networks.
 */
check(webauthn_xmlrpc_refused($lan_other, $settings), 'R5 XMLRPC from a LAN host outside trusted networks/peers refused');
check(!webauthn_xmlrpc_refused($lan_trusted, $settings), 'R5 XMLRPC from a trusted network allowed');
$peers = array_merge($settings, ['xmlrpc_peers' => '10.0.0.66']);
check(!webauthn_xmlrpc_refused(webauthn_request_source(['REMOTE_ADDR' => '10.0.0.66'], $peers), $peers), 'R5 XMLRPC from a configured peer allowed');
$off = array_merge($settings, ['enable' => '']);
check(!webauthn_xmlrpc_refused(webauthn_request_source(['REMOTE_ADDR' => '10.0.0.66'], $off), $off), 'R5 second factor off: pfSense behaviour unchanged');
check(webauthn_xmlrpc_refused(webauthn_request_source(['REMOTE_ADDR' => '10.0.0.66', 'HTTP_CF_RAY' => 'x'], $off), $off),
    'R5 proxied XMLRPC still refused when the second factor is off');
check(!empty(webauthn_validate_settings(array_merge($settings, ['xmlrpc_peers' => '0.0.0.0/0']))), 'R5 /0 XMLRPC peer refused');
check(!empty(webauthn_validate_settings(array_merge($settings, ['xmlrpc_peers' => 'peer.example']))), 'R5 invalid XMLRPC peer refused');
check(empty(webauthn_validate_settings(array_merge($settings, ['xmlrpc_peers' => '10.10.10.2']))), 'R5 XMLRPC peer accepted');

/*
 * R7. The used-nonce list is the only replay barrier for authenticators
 * with a zero counter. A damaged list must not make used challenges
 * valid again; it is written atomically and survives reboots (/conf).
 */
$_COOKIE = [];
$ch = webauthn_new_challenge('login', 'admin');
$cd = json_encode(['type' => 'webauthn.get', 'challenge' => webauthn_b64url_encode($ch)]);
check(webauthn_take_challenge('login', 'admin', $cd) !== null, 'R7 fresh challenge accepted');
check(webauthn_take_challenge('login', 'admin', $cd) === null, 'R7 challenge single-use');
file_put_contents(WEBAUTHN_USED_FILE, '');
check(webauthn_take_challenge('login', 'admin', $cd) === null, 'R7 challenge stays single-use after the used-nonce file is emptied');
$ch2 = webauthn_new_challenge('login', 'admin');
$cd2 = json_encode(['type' => 'webauthn.get', 'challenge' => webauthn_b64url_encode($ch2)]);
touch(WEBAUTHN_USED_FILE, time() - WEBAUTHN_CHALLENGE_TTL - 5);
check(webauthn_take_challenge('login', 'admin', $cd2) !== null, 'R7 a damaged list older than the challenge lifetime is reset');
check(str_starts_with(WEBAUTHN_USED_FILE, $tmp) && str_contains(file_get_contents("$pkg/webauthn.inc"), "'/conf/webauthn_used_challenges.json'"),
    'R7 used-nonce list kept in /conf');

/* Counter and key files are written whole. */
webauthn_set_sign_count('abc', 7);
check(webauthn_get_sign_count('abc') === 7 && !file_exists(WEBAUTHN_COUNTER_FILE . '.tmp'), 'counter written atomically');
@unlink(WEBAUTHN_KEY_FILE);
$k1 = webauthn_hmac_key();
check(strlen($k1) === 32 && webauthn_hmac_key() === $k1 && (fileperms(WEBAUTHN_KEY_FILE) & 0777) === 0600, 'key created once, mode 0600');

foreach ([WEBAUTHN_USED_FILE, WEBAUTHN_COUNTER_FILE] as $f) {
	@unlink($f);
	@unlink("$f.lock");
}
echo "$count checks, $failures failed\n";
exit($failures ? 1 : 0);
