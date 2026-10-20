<?php
/*
 * Off-box tests: php tests/run.php
 * Stubs the few pfSense functions the package uses.
 */

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
if (!function_exists("gettext")) { function gettext($s) { return $s; } }

$tmp = sys_get_temp_dir();
define('WEBAUTHN_COUNTER_FILE', "$tmp/webauthn-test-count.json");
define('WEBAUTHN_KEY_FILE', "$tmp/webauthn-test.key");
define('WEBAUTHN_USED_FILE', "$tmp/webauthn-test-used.json");

$root = dirname(__DIR__) . '/src/usr/local/pkg/webauthn';
require_once("$root/webauthn.inc");
require_once("$root/hook.inc");
require_once("$root/gate.inc");

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
function throws(callable $f, $name, $needle = '') {
	try {
		$f();
		check(false, "$name (no exception)");
	} catch (Exception $e) {
		check($needle === '' || str_contains($e->getMessage(), $needle), "$name (got: {$e->getMessage()})");
	}
}

require_once(__DIR__ . '/helpers.inc');

/* ---- CBOR ---- */
check(webauthn_cbor_decode("\x18\x64") === 100, 'cbor uint');
check(webauthn_cbor_decode("\x38\x63") === -100, 'cbor negint');
check(webauthn_cbor_decode("\x63abc") === 'abc', 'cbor text');
check(webauthn_cbor_decode("\xa1\x01\x02") === [1 => 2], 'cbor map');
throws(fn() => webauthn_cbor_decode("\x9f\x01\xff"), 'cbor indefinite rejected');
throws(fn() => webauthn_cbor_decode("\x01\x02"), 'cbor trailing rejected');
throws(fn() => webauthn_cbor_decode("\x5a\xff\xff\xff\xff"), 'cbor truncated');

/* ---- Ceremonies ---- */
$public = 'https://pfsense.example.com';
foreach ([WEBAUTHN_ALG_ES256 => 'ES256', WEBAUTHN_ALG_RS256 => 'RS256', WEBAUTHN_ALG_EDDSA => 'EdDSA'] as $alg => $name) {
	$a = new FakeAuthenticator($alg);
	$ch = random_bytes(32);
	[$cd, $att] = $a->create($ch, 'pfsense.example.com', $public);
	$reg = webauthn_verify_registration($cd, $att, $ch, 'pfsense.example.com', [$public], false);
	check($reg['credential_id'] === $a->id && $reg['alg'] === $alg, "$name registration");
	$cred = ['alg' => $reg['alg'], 'pem' => $reg['pem'], 'sign_count' => $reg['sign_count']];

	$ch = random_bytes(32);
	[$cd, $ad, $sig] = $a->get($ch, 'pfsense.example.com', $public);
	$n = webauthn_verify_assertion($cred, $cd, $ad, $sig, $ch, 'pfsense.example.com', [$public], false);
	check($n === 1, "$name assertion");
	$cred['sign_count'] = $n;

	[$cd, $ad, $sig] = $a->get($ch, 'pfsense.example.com', $public);
	throws(fn() => webauthn_verify_assertion($cred, $cd, $ad, $sig . '', random_bytes(32), 'pfsense.example.com', [$public], false),
	    "$name wrong challenge", 'Challenge');
	$bad = $sig;
	$bad[10] = chr(ord($bad[10]) ^ 1);
	throws(fn() => webauthn_verify_assertion($cred, $cd, $ad, $bad, $ch, 'pfsense.example.com', [$public], false),
	    "$name tampered signature");
}

$a = new FakeAuthenticator(WEBAUTHN_ALG_ES256);
$ch = random_bytes(32);
[$cd, $att] = $a->create($ch, 'pfsense.example.com', $public);
throws(fn() => webauthn_verify_registration($cd, $att, $ch, 'pfsense.example.com', ['https://evil.example'], false), 'origin not allowed', 'Origin');
throws(fn() => webauthn_verify_registration($cd, $att, $ch, 'example.com', [$public], false), 'rp id hash mismatch', 'RP ID');
[$cd, $att] = $a->create($ch, 'pfsense.example.com', $public, WEBAUTHN_FLAG_UP);
throws(fn() => webauthn_verify_registration($cd, $att, $ch, 'pfsense.example.com', [$public], true), 'uv required', 'User verification');
[$cd, $att] = $a->create($ch, 'pfsense.example.com', $public, 0x00);
throws(fn() => webauthn_verify_registration($cd, $att, $ch, 'pfsense.example.com', [$public], false), 'up required', 'presence');
[$cd, $att] = $a->create($ch, 'pfsense.example.com', 'http://pfsense.example.com');
throws(fn() => webauthn_verify_registration($cd, $att, $ch, 'pfsense.example.com', [$public], false), 'http origin rejected', 'Origin');

/* Origin trailing slash / case normalised. */
[$cd, $att] = $a->create($ch, 'pfsense.example.com', $public);
check(is_array(webauthn_verify_registration($cd, $att, $ch, 'pfsense.example.com', ['HTTPS://PFSENSE.example.com/'], false)), 'origin normalised');

/* Counter regression. */
$reg = webauthn_verify_registration($cd, $att, $ch, 'pfsense.example.com', [$public], false);
$cred = ['alg' => $reg['alg'], 'pem' => $reg['pem'], 'sign_count' => 5];
$a->count = 3;
[$cd, $ad, $sig] = $a->get($ch, 'pfsense.example.com', $public, 0x05, false);
throws(fn() => webauthn_verify_assertion($cred, $cd, $ad, $sig, $ch, 'pfsense.example.com', [$public], false), 'counter regression', 'counter');
/* Counter 0 on both sides (synced passkeys) is accepted. */
$a->count = 0;
[$cd, $ad, $sig] = $a->get($ch, 'pfsense.example.com', $public, 0x05, false);
$cred['sign_count'] = 0;
check(webauthn_verify_assertion($cred, $cd, $ad, $sig, $ch, 'pfsense.example.com', [$public], false) === 0, 'zero counters accepted');

/* Parent-domain RP ID: one passkey on public and LAN hostnames. */
$lan = 'https://pfsense.lan.example.com';
$b = new FakeAuthenticator(WEBAUTHN_ALG_ES256);
[$cd, $att] = $b->create($ch, 'example.com', $public);
$reg = webauthn_verify_registration($cd, $att, $ch, 'example.com', [$public, $lan], false);
$cred = ['alg' => $reg['alg'], 'pem' => $reg['pem'], 'sign_count' => 0];
[$cd, $ad, $sig] = $b->get($ch, 'example.com', $lan);
check(webauthn_verify_assertion($cred, $cd, $ad, $sig, $ch, 'example.com', [$public, $lan], false) === 1, 'parent RP ID on LAN hostname');

/* ---- Origin / RP ID rules ---- */
check(webauthn_origin_matches_rp('https://pfsense.example.com', 'example.com'), 'subdomain matches parent');
check(webauthn_origin_matches_rp('https://pfsense.example.com', 'pfsense.example.com'), 'exact match');
check(!webauthn_origin_matches_rp('https://evilexample.com', 'example.com'), 'suffix without dot rejected');
check(!webauthn_origin_matches_rp('http://pfsense.example.com', 'example.com'), 'http rejected');
check(!webauthn_origin_matches_rp('https://192.168.1.1', '192.168.1.1'), 'IP RP ID rejected');
check(!webauthn_origin_matches_rp('https://pfsense.example.com/path', 'example.com'), 'path rejected');

/* ---- Settings validation ---- */
$base = webauthn_default_settings();
check(empty(webauthn_validate_settings(array_merge($base, ['enable' => 'yes', 'rp_id' => 'example.com',
    'origins' => "https://pfsense.example.com\nhttps://pfsense.lan.example.com", 'trusted_proxies' => '127.0.0.1',
    'trusted_networks' => '192.168.1.0/24 fd00::/64']))), 'valid settings accepted');
check(!empty(webauthn_validate_settings(array_merge($base, ['rp_id' => '192.168.1.1']))), 'IP RP ID refused');
check(!empty(webauthn_validate_settings(array_merge($base, ['rp_id' => 'pfsense.example.com', 'origins' => 'https://other.example']))), 'foreign origin refused');
check(!empty(webauthn_validate_settings(array_merge($base, ['trusted_networks' => '0.0.0.0/0']))), '/0 refused');
check(!empty(webauthn_validate_settings(array_merge($base, ['trusted_proxies' => '10.0.0.300']))), 'bad IP refused');
check(!empty(webauthn_validate_settings(array_merge($base, ['enable' => 'yes']))), 'enable without RP ID refused');

/* ---- Access path ---- */
$s = array_merge($base, ['enable' => 'yes', 'rp_id' => 'pfsense.example.com',
    'trusted_proxies' => '192.168.1.5', 'trusted_networks' => '192.168.1.0/24']);

$src = webauthn_request_source(['REMOTE_ADDR' => '192.168.1.5', 'HTTP_CF_CONNECTING_IP' => '203.0.113.9'], $s);
check($src['via_proxy'] && $src['client'] === '203.0.113.9', 'CF-Connecting-IP trusted from cloudflared');
check(!webauthn_source_is_trusted_network($src, $s), 'tunnel traffic not exempt although cloudflared is on the LAN');
check(webauthn_gate_decision($s, $src, true) === 'require', 'tunnel requires WebAuthn');

$src = webauthn_request_source(['REMOTE_ADDR' => '198.51.100.7', 'HTTP_CF_CONNECTING_IP' => '1.2.3.4'], $s);
check(!$src['via_proxy'] && $src['client'] === '198.51.100.7', 'CF-Connecting-IP ignored from other peers');

$src = webauthn_request_source(['REMOTE_ADDR' => '192.168.1.20'], $s);
check(webauthn_source_is_trusted_network($src, $s), 'LAN client exempt');
check(webauthn_gate_decision($s, $src, true) === 'skip', 'LAN skips');

$src = webauthn_request_source(['REMOTE_ADDR' => '192.168.1.20', 'HTTP_CF_RAY' => 'x'], $s);
check(!webauthn_source_is_trusted_network($src, $s), 'LAN peer with CF headers not exempt');

/* cloudflared on the LAN but not configured as cloudflared source. */
$noproxy = array_merge($s, ['trusted_proxies' => '']);
$src = webauthn_request_source(['REMOTE_ADDR' => '192.168.1.5', 'HTTP_X_FORWARDED_FOR' => '203.0.113.50'], $noproxy);
check(!webauthn_source_is_trusted_network($src, $noproxy) && webauthn_gate_decision($noproxy, $src, true) === 'require',
    'forwarded request from unconfigured cloudflared on LAN not exempt');

$src = webauthn_request_source(['REMOTE_ADDR' => '127.0.0.1', 'HTTP_CF_CONNECTING_IP' => '203.0.113.9'],
    array_merge($s, ['trusted_proxies' => '127.0.0.1', 'trusted_networks' => '127.0.0.0/8']));
check(!webauthn_source_is_trusted_network($src, array_merge($s, ['trusted_proxies' => '127.0.0.1', 'trusted_networks' => '127.0.0.0/8'])),
    'cloudflared on localhost never exempt');

$src = webauthn_request_source(['REMOTE_ADDR' => '203.0.113.9'], $s);
check(webauthn_gate_decision($s, $src, false) === 'skip', 'no passkey, not enforced: skip');
check(webauthn_gate_decision(array_merge($s, ['enforce' => 'yes']), $src, false) === 'deny', 'no passkey, enforced: deny');
check(webauthn_gate_decision(array_merge($s, ['enable' => '']), $src, true) === 'skip', 'disabled: skip');

check(webauthn_ip_in_cidr('fd00::1', 'fd00::/64') && !webauthn_ip_in_cidr('fd01::1', 'fd00::/64'), 'ipv6 cidr');
check(webauthn_ip_in_cidr('10.1.2.3', '10.0.0.0/9') && !webauthn_ip_in_cidr('10.128.0.1', '10.0.0.0/9'), 'ipv4 cidr partial byte');
check(!webauthn_ip_in_cidr('10.0.0.1', 'fd00::/8'), 'family mismatch');

check(webauthn_allowed_origins($s) === ['https://pfsense.example.com'], 'default origin from RP ID');

/* ---- Credential storage (pfSense XML shape) ---- */

/*
 * Mirror of pfSense's dump_xml_config_sub(): a numeric array key is only
 * valid as an element of a list tag; anywhere else it becomes <0>.
 */
function xml_safe($arr, $parent = null) {
	$listtags = ['config', 'item', 'row', 'menu'];
	foreach ($arr as $k => $v) {
		if (is_int($k) && !in_array($parent, $listtags, true)) {
			return false;
		}
		if (is_array($v) && !xml_safe($v, is_int($k) ? null : $k)) {
			return false;
		}
	}
	return true;
}
$saved = $GLOBALS['test_config'];
$GLOBALS['test_config'] = [];
config_set_path(WEBAUTHN_CONFIG_PATH, webauthn_default_settings());
$a = new FakeAuthenticator(WEBAUTHN_ALG_ES256);
$ch = random_bytes(32);
[$cd, $att] = $a->create($ch, 'pfsense.example.com', $public);
webauthn_add_credential('admin', 'Proton Pass', webauthn_verify_registration($cd, $att, $ch, 'pfsense.example.com', [$public], false), 'pfsense.example.com');
check(xml_safe($GLOBALS['test_config']), 'stored passkey serialises to valid pfSense XML');
check(count(webauthn_get_credentials('admin')) === 1, 'stored passkey listed');
webauthn_delete_credential(webauthn_get_credentials('admin')[0]['id']);
check(xml_safe($GLOBALS['test_config']) && webauthn_get_credentials() === [], 'XML valid after delete');
$GLOBALS['test_config'] = $saved;

$saved = $GLOBALS['test_config'];
$one = ['username' => 'admin', 'name' => 'Proton Pass', 'id' => 'abc', 'alg' => '-7', 'publickey' => 'x', 'rp_id' => 'r', 'created' => '0'];
config_set_path(WEBAUTHN_CRED_PATH, $one);
check(count(webauthn_get_credentials('admin')) === 1, 'lone <credential> element read as one passkey');
check(webauthn_delete_credential('abc', 'admin') && count(webauthn_get_credentials()) === 0, 'lone credential deletable');
config_set_path(WEBAUTHN_CRED_PATH, [$one, array_merge($one, ['id' => 'def', 'username' => 'bob'])]);
check(count(webauthn_get_credentials()) === 2 && count(webauthn_get_credentials('bob')) === 1, 'credential list read');
config_set_path(WEBAUTHN_CRED_PATH, '');
check(webauthn_get_credentials() === [], 'empty credential element');
$GLOBALS['test_config'] = $saved;

/* ---- Challenges ---- */
function cd_for($ch) {
	return json_encode(['type' => 'webauthn.create', 'challenge' => webauthn_b64url_encode($ch)]);
}
$c1 = webauthn_new_challenge('register', 'admin');
$c2 = webauthn_new_challenge('register', 'admin');
check(webauthn_take_challenge('register', 'admin', cd_for($c1)) === $c1, 'older challenge still valid after a reload');
check(webauthn_take_challenge('register', 'admin', cd_for($c1)) === null, 'challenge single use');
check(webauthn_take_challenge('login', 'admin', cd_for($c2)) === null, 'challenge bound to purpose');
check(webauthn_take_challenge('register', 'bob', cd_for($c2)) === null, 'challenge bound to user');
$t = $c2;
$t[0] = chr(ord($t[0]) ^ 1);
check(webauthn_take_challenge('register', 'admin', cd_for($t)) === null, 'forged challenge refused');
$payload = random_bytes(16) . pack('N', time() - 1);
$old = $payload . webauthn_challenge_mac('register', 'admin', $payload);
check(webauthn_take_challenge('register', 'admin', cd_for($old)) === null, 'expired challenge refused');
check(webauthn_take_challenge('register', 'admin', '{}') === null, 'missing challenge refused');
check(webauthn_take_challenge('register', 'admin', cd_for($c2)) === $c2, 'second challenge valid');

/* ---- Redirects ---- */
check(webauthn_safe_redirect('/firewall_rules.php?if=wan') === '/firewall_rules.php?if=wan', 'local redirect kept');
check(webauthn_safe_redirect('//evil.example/') === '/', 'protocol-relative redirect refused');
check(webauthn_safe_redirect('https://evil.example/') === '/', 'absolute redirect refused');

/* ---- authgui.inc hook ---- */
$authgui = "<?php\nrequire_once('pfsense-utils.inc');\n\n/* Authenticate user - exit if failed */\nif (!session_auth()) {\n\tdisplay_login_form();\n\texit;\n}\n\nphpsession_begin();\n";
$patched = webauthn_hook_apply($authgui);
check($patched !== null && strpos($patched, 'webauthn_gate();') > strpos($patched, 'display_login_form') &&
    strpos($patched, 'webauthn_gate();') < strpos($patched, 'phpsession_begin'), 'hook inserted after session_auth');
check(webauthn_hook_apply($patched) === $patched, 'hook idempotent');
check(webauthn_hook_remove($patched) === $authgui, 'hook removable');
check(webauthn_hook_apply("<?php\n") === null, 'hook refuses unknown file');
$real = __DIR__ . '/fixtures/authgui.inc';
if (file_exists($real)) {
	check(webauthn_hook_apply(file_get_contents($real)) !== null, 'hook applies to real authgui.inc');
}

echo "$count checks, $failures failed\n";
exit($failures ? 1 : 0);
