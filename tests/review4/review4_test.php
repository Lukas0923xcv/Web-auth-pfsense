<?php
/*
 * Regression tests for the fourth review (REVIEW4.md):
 *   php tests/review4/review4_test.php
 */
$tmp = sys_get_temp_dir();
define('WEBAUTHN_COUNTER_FILE', "$tmp/webauthn-r4-count.json");
define('WEBAUTHN_KEY_FILE', "$tmp/webauthn-r4.key");
define('WEBAUTHN_USED_FILE', "$tmp/webauthn-r4-used.json");
define('WEBAUTHN_REVOKED_FILE', "$tmp/webauthn-r4-revoked.json");
define('WEBAUTHN_CONFIG_LOCK', "$tmp/webauthn-r4-config");
define('WEBAUTHN_NOTICE_FILE', "$tmp/webauthn-r4-notices.json");
foreach ([WEBAUTHN_COUNTER_FILE, WEBAUTHN_USED_FILE, WEBAUTHN_REVOKED_FILE, WEBAUTHN_NOTICE_FILE] as $f) {
	@unlink($f);
}

/*
 * pfSense keeps the config of the request in memory ($test_config) and
 * write_config() writes all of it to disk ($disk); config_read_file()
 * loads the disk copy. That is the snapshot effect behind finding 3.
 */
$GLOBALS['test_config'] = [];
$GLOBALS['disk'] = [];
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
function write_config($desc) {
	$GLOBALS['last_desc'] = $desc;
	$GLOBALS['disk'] = $GLOBALS['test_config'];
	return $GLOBALS['disk'];
}
function config_read_file(bool $use_backup = false, bool $use_cache = true): bool {
	$GLOBALS['test_config'] = $GLOBALS['disk'];
	return true;
}
function file_notice($id, $notice, $category = 'General', $url = '', $priority = 1, $local_only = false) {
	$GLOBALS['notices'][] = $notice;
}
function phpsession_begin() {}
function phpsession_end($w = false) {}
if (!function_exists('gettext')) {
	function gettext($s) { return $s; }
}

$repo = dirname(__DIR__, 2);
$pkg = "$repo/src/usr/local/pkg/webauthn";
require_once("$pkg/gate.inc");
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
]);
$tunnel = webauthn_request_source(['REMOTE_ADDR' => '192.168.1.5', 'HTTP_CF_CONNECTING_IP' => '203.0.113.9'], $settings);
$lan_trusted = webauthn_request_source(['REMOTE_ADDR' => '192.168.1.20'], $settings);
$ldap = ['remoteauth' => true, 'authsource' => 'LDAP/corp'];
$local = ['remoteauth' => true, 'authsource' => 'Local Database'];
$users = [['name' => 'admin', 'uid' => '0'], ['name' => '1000', 'uid' => '2000'], ['name' => 'carol', 'uid' => '2001']];

function reset_config(array $settings, array $users): void {
	$GLOBALS['test_config'] = ['installedpackages' => ['webauthn' => ['config' => [$settings], 'item' => []]],
	    'system' => ['user' => $users]];
	$GLOBALS['disk'] = $GLOBALS['test_config'];
}
/* Register a passkey for $user through the real code path; returns its ID. */
function register(array $settings, string $user, string $uid = ''): string {
	$a = new FakeAuthenticator(WEBAUTHN_ALG_ES256);
	$ch = random_bytes(32);
	[$cd, $att] = $a->create($ch, $settings['rp_id'], 'https://' . $settings['rp_id']);
	$reg = webauthn_verify_registration($cd, $att, $ch, $settings['rp_id'], ['https://' . $settings['rp_id']], false);
	$err = webauthn_add_credential($user, 'key', $reg, $settings['rp_id'], $uid);
	check($err === null, "setup: passkey for '$user' registered (" . var_export($err, true) . ')');
	return webauthn_b64url_encode($reg['credential_id']);
}
function verified(string $user, string $id, string $rp, array $extra = []): array {
	return ['user' => $user, 'method' => 'webauthn', 'credential' => $id, 'time' => time(), 'sid' => '', 'rp_id' => $rp, 'uv' => false] + $extra;
}

/* ---- 1. Signature counter advanced atomically ---- */
webauthn_set_sign_count('c1', 9);
check(webauthn_advance_sign_count('c1', 50), '1: 9 -> 50 accepted');
check(!webauthn_advance_sign_count('c1', 10), '1: 50 -> 10 refused (clone or replay)');
check(webauthn_get_sign_count('c1') === 50, '1: stored counter stays 50');
check(!webauthn_advance_sign_count('c1', 50), '1: equal counter refused');
check(webauthn_advance_sign_count('c0', 0) && webauthn_advance_sign_count('c0', 0), '1: authenticators without a counter (0/0) accepted');
@mkdir(WEBAUTHN_COUNTER_FILE . '.' . getmypid() . '.tmp');
check(!webauthn_advance_sign_count('c1', 60), '1: counter that cannot be stored refused');
check(!webauthn_set_sign_count('c1', 61), '1: set_sign_count reports a failed write');
@rmdir(WEBAUTHN_COUNTER_FILE . '.' . getmypid() . '.tmp');

reset_config($settings, $users);
$a = new FakeAuthenticator(WEBAUTHN_ALG_ES256);
$ch = random_bytes(32);
[$cd, $att] = $a->create($ch, $rp, "https://$rp");
$reg = webauthn_verify_registration($cd, $att, $ch, $rp, ["https://$rp"], false);
@mkdir(WEBAUTHN_COUNTER_FILE . '.' . getmypid() . '.tmp');
$err = webauthn_add_credential('admin', 'key', $reg, $rp);
@rmdir(WEBAUTHN_COUNTER_FILE . '.' . getmypid() . '.tmp');
check($err !== null && webauthn_get_credentials('admin') === [], '1: registration aborts when its counter cannot be stored');
$id = register($settings, 'admin');
webauthn_delete_credential($id, null);
check(!array_key_exists($id, json_decode((string)file_get_contents(WEBAUTHN_COUNTER_FILE), true) ?? []), '1: counter entry removed with the passkey');

/* ---- 2. Verified state bound to the login, its age, RP ID and UV ---- */
reset_config($settings, $users);
$id = register($settings, 'admin');
$s = ['Username' => 'admin', 'webauthn' => verified('admin', $id, $rp)] + $ldap;
check(webauthn_session_status($settings, $s, $tunnel) === 'verified', '2: fresh verification valid');
$old = $s;
$old['webauthn']['time'] = time() - WEBAUTHN_VERIFIED_MAX_AGE - 1;
check(webauthn_session_status($settings, $old, $tunnel) === 'require', '2: verification older than the maximum age requires again');
$future = $s;
$future['webauthn']['time'] = time() + 3600;
check(webauthn_session_status($settings, $future, $tunnel) === 'require', '2: verification time in the future requires again');
$other = $s;
$other['webauthn']['sid'] = 'previous-session-id';
check(webauthn_session_status($settings, $other, $tunnel) === 'require', '2: verification of another session ID (new password login) requires again');
$legacy = $s;
unset($legacy['webauthn']['sid'], $legacy['webauthn']['rp_id']);
check(webauthn_session_status($settings, $legacy, $tunnel) === 'require', '2: verification state of an older version requires again');
check(webauthn_session_status(array_merge($settings, ['rp_id' => 'example.com', 'origins' => 'https://pfsense.example.com']), $s, $tunnel) === 'require',
    '2: RP ID changed: requires again');
$uvreq = array_merge($settings, ['user_verification' => 'required']);
check(webauthn_session_status($uvreq, $s, $tunnel) === 'require', '2: UV now required, verified without UV: requires again');
$s_uv = $s;
$s_uv['webauthn']['uv'] = true;
check(webauthn_session_status($uvreq, $s_uv, $tunnel) === 'verified', '2: UV now required, verified with UV: still valid');
check(webauthn_session_status($settings, $old, $lan_trusted) === 'skip', '2: an expired verification on a trusted network skips as designed');
$_POST = ['login' => 'Sign In', 'usernamefld' => 'admin'];
$GLOBALS['test_config']['installedpackages']['webauthn']['config'][0] = $settings;
check(webauthn_is_login_post() && !webauthn_cached_privileges_allowed(), '2: auth_check.inc fast path refused for a login POST');
$_POST = [];
$a = new FakeAuthenticator(WEBAUTHN_ALG_ES256);
$ch = random_bytes(32);
[$cd, $att] = $a->create($ch, $rp, "https://$rp");
$a->count = 0;
$reg = webauthn_verify_registration($cd, $att, $ch, $rp, ["https://$rp"], false);
$cred = ['alg' => $reg['alg'], 'pem' => $reg['pem'], 'sign_count' => 0];
$ch = random_bytes(32);
[$cd, $ad, $sig] = $a->get($ch, $rp, "https://$rp", 0x05);
webauthn_verify_assertion($cred, $cd, $ad, $sig, $ch, $rp, ["https://$rp"], false, $info);
check(($info['uv'] ?? null) === true, '2: verify_assertion reports UV');
$ch = random_bytes(32);
[$cd, $ad, $sig] = $a->get($ch, $rp, "https://$rp", 0x01);
check(webauthn_verify_assertion($cred, $cd, $ad, $sig, $ch, $rp, ["https://$rp"], false) === $a->count, '2: verify_assertion API unchanged without $info');

/* ---- 3. Lost update: a removed passkey cannot come back ---- */
reset_config($settings, $users);
$x = register($settings, 'admin');
$stale = $GLOBALS['test_config'];                 /* request A started now: it still sees X */
check(webauthn_delete_credential($x, null), '3: request B removes X');
$GLOBALS['test_config'] = $stale;                 /* back in request A */
$y = register($settings, 'carol');                /* A writes after B */
$disk_ids = array_column($GLOBALS['disk']['installedpackages']['webauthn']['item'] ?? [], 'id');
check(!in_array($x, $disk_ids, true) && in_array($y, $disk_ids, true), '3: a change from an older snapshot does not bring X back');
$GLOBALS['test_config'] = $stale;                 /* another page writes its whole stale config */
write_config('unrelated change');
check(webauthn_find_credential('admin', $x) === null && webauthn_get_credentials('admin') === [], '3: X brought back by a stale write stays revoked');
reset_config($settings, $users);
$dup = register($settings, 'admin');
$rec = $GLOBALS['test_config']['installedpackages']['webauthn']['item'][0];
config_set_path(WEBAUTHN_CRED_PATH, [$rec, $rec]);
write_config('duplicate');
check(webauthn_delete_credential($dup, null) && empty($GLOBALS['disk']['installedpackages']['webauthn']['item']), '3: every record with the ID is removed');

/* ---- 4. LDAP/RADIUS spellings: kana, %, missing intl/mbstring ---- */
reset_config($settings, $users);
register($settings, 'タロウ');
check(webauthn_session_status($settings, ['Username' => 'たろう'] + $ldap, $tunnel) === 'require', '4: hiragana login for a katakana owner requires');
check(webauthn_session_status($settings, ['Username' => 'ﾀﾛｳ'] + $ldap, $tunnel) === 'require', '4: half-width katakana login requires');
register($settings, 'taro');
check(webauthn_session_status($settings, ['Username' => 'taro%realm'] + $ldap, $tunnel) === 'require', '4: "taro%realm" requires the passkey of "taro"');
check(webauthn_session_status($settings, ['Username' => 'jiro'] + $ldap, $tunnel) === 'skip', '4: an unrelated LDAP user without passkeys still skips');
webauthn_unicode_available(false);
check(webauthn_session_status($settings, ['Username' => 'ｔａｒｏ'] + $ldap, $tunnel) !== 'skip', '4: without intl/mbstring a remote session does not skip while passkeys exist');
check(webauthn_session_status($settings, ['Username' => 'carol'] + $local, $tunnel) === 'skip', '4: ...local accounts stay exact');
webauthn_unicode_available(true);

/* ---- 5. Local sessions: identity from the user database ---- */
reset_config($settings, $users);
register($settings, '1000', '2000');
check(webauthn_session_identity(['Username' => '1000'] + $local) === '1000', '5: local name resolves to its account');
check(webauthn_session_identity(['Username' => '1e3'] + $local) === '', '5: "1e3" is not account "1000" (exact match, as pfSense\'s index)');
check(webauthn_session_status($settings, ['Username' => '1e3'] + $local, $tunnel) === 'require', '5: unresolvable local name requires (fail closed), not skip');
check(webauthn_session_status($settings, ['Username' => '1000'] + $local, $tunnel) === 'require', '5: account with a passkey requires');
check(webauthn_session_status($settings, ['Username' => 'nobody'] + $local, $tunnel) === 'require', '5: unknown local account requires');
check(webauthn_session_identity(['Username' => 'Someone@x'] + $ldap) === 'Someone@x', '5: remote names unchanged');

/* ---- 6. Names in notices and config history are plain one-line text ---- */
$evil = "eve\n2026-01-01 webauthn: forged\r\x0b\u{202E}gnp.exe\u{2028}x" . "\xff";
$plain = webauthn_plain($evil);
check(!preg_match('/[\x00-\x1f\x7f]|\x{202E}|\x{2028}/u', $plain) && preg_match('//u', $plain) === 1, '6: control, bidi and separator characters removed, valid UTF-8');
check(mb_strlen(webauthn_plain(str_repeat('a', 300))) <= 65, '6: shortened');
$GLOBALS['notices'] = [];
webauthn_notice('user "' . $evil . '" did something');
check(count($GLOBALS['notices']) === 1 && !preg_match('/[\x00-\x1f]|\x{202E}/u', $GLOBALS['notices'][0]), '6: notice text is plain');
reset_config($settings, $users);
$a = new FakeAuthenticator(WEBAUTHN_ALG_ES256);
$ch = random_bytes(32);
[$cd, $att] = $a->create($ch, $rp, "https://$rp");
webauthn_add_credential("eve\nx@corp", 'key', webauthn_verify_registration($cd, $att, $ch, $rp, ["https://$rp"], false), $rp);
check(!preg_match('/[\x00-\x1f]/', (string)$GLOBALS['last_desc']), '6: config history description is plain');

/* ---- 7. Passkey names ---- */
foreach (["a\x0bb", "x\ny", "bad\xff", '<b>', '', str_repeat('a', 65), "a\u{202E}b"] as $bad) {
	check(!webauthn_valid_passkey_name($bad), '7: name ' . json_encode(mb_scrub($bad)) . ' refused');
}
foreach (['YubiKey 5 (blau)', 'iPhone_15-Pro', 'Schlüssel 2', str_repeat('a', 64)] as $good) {
	check(webauthn_valid_passkey_name($good), "7: name '$good' accepted");
}

/* ---- 8. Passkeys of deleted accounts, revocation ---- */
reset_config($settings, $users);
$cid = register($settings, 'carol', '2001');
check(count(webauthn_get_credentials('carol')) === 1, '8: passkey of the account counts');
$GLOBALS['test_config']['system']['user'][2]['uid'] = '2002';   /* carol deleted, new carol created */
check(webauthn_get_credentials('carol') === [] && webauthn_find_credential('carol', $cid) === null, '8: passkey of a deleted account (other uid) ignored');
check(webauthn_orphaned(webauthn_get_credentials()[0]), '8: shown as orphaned');
unset($GLOBALS['test_config']['system']['user'][2]);
check(webauthn_get_credentials('carol') === [], '8: account gone: ignored');
reset_config($settings, $users);
$rid = register($settings, 'admin');
$rec = $GLOBALS['test_config']['installedpackages']['webauthn']['item'][0];
webauthn_delete_credential($rid, null);
config_set_path(WEBAUTHN_CRED_PATH, [$rec]);                     /* config restore */
check(webauthn_find_credential('admin', $rid) === null, '8: restored passkey stays revoked');
$GLOBALS['test_config']['installedpackages']['webauthn']['item'] = [];
$GLOBALS['disk'] = $GLOBALS['test_config'];
$a2 = new FakeAuthenticator(WEBAUTHN_ALG_ES256);
$a2->id = webauthn_b64url_decode($rid);
$ch = random_bytes(32);
[$cd, $att] = $a2->create($ch, $rp, "https://$rp");
check(webauthn_add_credential('admin', 'again', webauthn_verify_registration($cd, $att, $ch, $rp, ["https://$rp"], false), $rp) === null &&
    webauthn_find_credential('admin', $rid) !== null, '8: registering the same ID again makes it valid again');

/* A damaged revocation list fails closed: passkeys still count (no skipping), none is accepted, no change is made. */
reset_config($settings, $users);
$did = register($settings, 'admin');
file_put_contents(WEBAUTHN_REVOKED_FILE, '{damaged');
check(webauthn_find_credential('admin', $did) === null, '8: damaged revocation list: no passkey accepted');
check(webauthn_session_status($settings, ['Username' => 'admin'] + $ldap, $tunnel) === 'require', '8: ...and the passkey step is not skipped');
check(!webauthn_delete_credential($did, null) && count(webauthn_get_credentials('admin')) === 1, '8: ...removal refused, record kept');
$a3 = new FakeAuthenticator(WEBAUTHN_ALG_ES256);
$ch = random_bytes(32);
[$cd, $att] = $a3->create($ch, $rp, "https://$rp");
check(webauthn_add_credential('carol', 'k', webauthn_verify_registration($cd, $att, $ch, $rp, ["https://$rp"], false), $rp) !== null,
    '8: ...registration refused');
unlink(WEBAUTHN_REVOKED_FILE);

/* ---- 9. Hardening ---- */
reset_config($settings, $users);
$hid = register($settings, 'admin');
$off = array_merge($settings, ['enable' => '']);
check(!webauthn_may_register($off, ['Username' => 'admin'] + $local, $tunnel, false), '9: second factor off: a user with a passkey may not add one');
check(webauthn_may_register($off, ['Username' => 'admin'] + $local, $tunnel, true), '9: ...an admin may');
check(webauthn_may_register($off, ['Username' => 'carol'] + $local, $tunnel, false), '9: ...the first passkey still needs only the password');
check(!webauthn_may_delete($settings, ['Username' => 'admin'] + $local, $lan_trusted, $hid, false), '9: non-admin may not remove the last passkey from a skip session');
check(webauthn_may_delete($settings, ['Username' => 'admin'] + $local, $lan_trusted, $hid, true), '9: admin may (recovery)');
check(webauthn_may_delete($settings, ['Username' => 'admin', 'webauthn' => verified('admin', $hid, $rp)] + $local, $tunnel, $hid, false),
    '9: non-admin with a verified session may');
register($settings, 'admin');
check(webauthn_may_delete($settings, ['Username' => 'admin'] + $local, $lan_trusted, $hid, false), '9: non-admin may remove one of two passkeys');
foreach (['10.0.0.0/7', '2001:db8::/15', '0.0.0.0/0', '::/00'] as $c) {
	check(!empty(webauthn_validate_settings(array_merge($settings, ['trusted_networks' => $c]))), "9: trusted network $c refused");
	check(!empty(webauthn_validate_settings(array_merge($settings, ['xmlrpc_peers' => $c]))), "9: XMLRPC peer $c refused");
}
foreach (['10.0.0.0/8', '2001:db8::/16', '192.168.1.10'] as $c) {
	check(empty(webauthn_validate_settings(array_merge($settings, ['trusted_networks' => $c]))), "9: trusted network $c accepted");
}
$mine = webauthn_get_credentials('admin');
check(webauthn_settings_lockout_error(array_merge($settings, ['rp_id' => 'other.example', 'origins' => '']), $tunnel, $mine) !== null,
    '9: saving an RP ID none of my passkeys has refused through the tunnel');
check(webauthn_settings_lockout_error(array_merge($settings, ['rp_id' => 'other.example', 'origins' => '']), $lan_trusted, $mine) === null,
    '9: ...allowed from a trusted network');
check(webauthn_settings_lockout_error($settings, $tunnel, $mine) === null, '9: keeping the RP ID allowed');
$GLOBALS['notices'] = [];
webauthn_notice('failures 1', 'failures:admin');
webauthn_notice('failures 2', 'failures:admin');
webauthn_notice('failures 3', 'failures:carol');
check(count($GLOBALS['notices']) === 2, '9: at most one failed-attempt notice per user in 15 minutes');
@unlink(WEBAUTHN_USED_FILE);
$live = [];
for ($i = 0; $i < WEBAUTHN_MAX_LIVE_NONCES; $i++) {
	$live[bin2hex(random_bytes(16))] = time() + 200;
}
file_put_contents(WEBAUTHN_USED_FILE, json_encode($live));
check(!webauthn_mark_nonce_used(bin2hex(random_bytes(16)), time() + 300), '9: used-challenge list full: refused (fail closed)');
@unlink(WEBAUTHN_USED_FILE);
$_COOKIE = [];
/* Only completed ceremonies fill the used-challenge list: without a passkey it cannot be filled up. */
$c = webauthn_new_challenge('login', 'admin');
$cdj = json_encode(['challenge' => webauthn_b64url_encode($c)]);
for ($i = 0; $i < 3; $i++) {
	try {
		webauthn_use_challenge('login', 'admin', $cdj, function ($ch) {
			throw new WebAuthnException('bad signature');
		});
	} catch (WebAuthnException $e) {
	}
}
check(!file_exists(WEBAUTHN_USED_FILE) || json_decode(file_get_contents(WEBAUTHN_USED_FILE), true) === [],
    '9: failed verifications do not use up challenges');
check(webauthn_use_challenge('login', 'admin', $cdj, function ($ch) { return 'ok'; }) === 'ok', '9: the challenge still works after failed tries');
check(webauthn_use_challenge('login', 'admin', $cdj, function ($ch) { return 'again'; }) === null, '9: ...and only once');
$c = webauthn_new_challenge('login', 'admin');
@mkdir(WEBAUTHN_USED_FILE . '.' . getmypid() . '.tmp');
$threw = false;
try {
	webauthn_use_challenge('login', 'admin', json_encode(['challenge' => webauthn_b64url_encode($c)]), function ($ch) { return 'ok'; });
} catch (WebAuthnException $e) {
	$threw = true;
}
@rmdir(WEBAUTHN_USED_FILE . '.' . getmypid() . '.tmp');
check($threw, '9: a success whose use cannot be recorded fails (fail closed)');
$payload = random_bytes(16) . pack('N', time() + WEBAUTHN_CHALLENGE_TTL + 120);
$far = $payload . webauthn_challenge_mac('login', 'admin', $payload);
check(webauthn_take_challenge('login', 'admin', json_encode(['challenge' => webauthn_b64url_encode($far)])) === null,
    '9: challenge expiring further ahead than possible (clock went back) refused');
$ok = webauthn_new_challenge('login', 'admin');
check(webauthn_take_challenge('login', 'admin', json_encode(['challenge' => webauthn_b64url_encode($ok)])) !== null, '9: fresh challenge accepted');
$jf = "$tmp/webauthn-r4-json.json";
@unlink($jf);
check(webauthn_write_json($jf, ['a' => 1]) && (fileperms($jf) & 0777) === 0600 && glob("$jf.*.tmp") === [], '9: JSON file written 0600, no temp file left');
@mkdir("$jf." . getmypid() . '.tmp');
check(!webauthn_write_json($jf, ['a' => 2]) && json_decode(file_get_contents($jf), true) === ['a' => 1], '9: failed write leaves the old file');
@rmdir("$jf." . getmypid() . '.tmp');
@unlink($jf);
$page = file_get_contents("$repo/src/usr/local/www/system_webauthn.php");
$regen = strpos($page, 'session_regenerate_id(true);');
check($regen !== false && $regen < strpos($page, "\$_SESSION['webauthn'] = webauthn_verified_state("),
    '9: registration rotates the session ID before recording the verification');

foreach ([WEBAUTHN_COUNTER_FILE, WEBAUTHN_USED_FILE, WEBAUTHN_REVOKED_FILE, WEBAUTHN_NOTICE_FILE] as $f) {
	@unlink($f);
	@unlink("$f.lock");
}
@unlink(WEBAUTHN_CONFIG_LOCK . '.lock');
echo "$count checks, $failures failed\n";
exit($failures ? 1 : 0);
