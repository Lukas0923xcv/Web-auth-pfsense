<?php
/*
 * Regression tests for the independent review of the fourth-review state
 * (REVIEW4.md, findings R4-I to R4-N): php tests/review4/review4b_test.php
 */
$dir = sys_get_temp_dir() . '/webauthn-r4b-' . getmypid();
@mkdir($dir);
putenv("WEBAUTHN_RACE_DIR=$dir");
function reset_dir(string $dir): void {
	foreach (glob("$dir/*") as $f) {
		unlink($f);
	}
}
reset_dir($dir);
require __DIR__ . '/race_stub.inc';

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
	'trusted_proxies' => '192.168.1.5', 'trusted_networks' => '192.168.1.0/24', 'enforce' => 'yes',
]);
$tunnel = webauthn_request_source(['REMOTE_ADDR' => '192.168.1.5', 'HTTP_CF_CONNECTING_IP' => '203.0.113.9'], $settings);
function setup_disk(array $settings, array $items, array $extra = []): void {
	$GLOBALS['test_config'] = array_replace_recursive(['system' => ['user' => [['name' => 'bob', 'uid' => '2000']]],
	    'installedpackages' => ['webauthn' => ['config' => [$settings], 'item' => $items]]], $extra);
	file_put_contents(RACE_DISK, serialize($GLOBALS['test_config']));
}
function rec(string $user, string $id, string $rp, array $extra = []): array {
	return ['username' => $user, 'name' => 'k', 'id' => $id, 'alg' => '-7', 'publickey' => '', 'rp_id' => $rp, 'created' => '0'] + $extra;
}
function make_reg(string $rp, ?string $id = null): array {
	$a = new FakeAuthenticator(WEBAUTHN_ALG_ES256);
	if ($id !== null) {
		$a->id = $id;
	}
	$ch = random_bytes(32);
	[$cd, $att] = $a->create($ch, $rp, "https://$rp");
	return webauthn_verify_registration($cd, $att, $ch, $rp, ["https://$rp"], false);
}

/* ---- R4-I: two parallel removals cannot both leave "the other one" ---- */
for ($run = 0; $run < 5; $run++) {
	reset_dir($dir);
	setup_disk($settings, [rec('bob', 'IDA', $rp, ['uid' => '2000']), rec('bob', 'IDB', $rp, ['uid' => '2000'])]);
	$start = microtime(true) + 0.3;
	$cmd = PHP_BINARY . ' ' . escapeshellarg(__DIR__ . '/race_delete.php');
	$p1 = popen("$cmd IDA $start", 'r');
	$p2 = popen("$cmd IDB $start", 'r');
	$out = stream_get_contents($p1) . stream_get_contents($p2);
	pclose($p1);
	pclose($p2);
	config_read_file();
	$left = count(webauthn_get_credentials('bob'));
	if ($left !== 1 || substr_count($out, 'deleted') !== 1) {
		break;
	}
}
check($left === 1 && substr_count($out, 'deleted') === 1, "R4-I parallel removals keep one passkey (left $left; " . trim(str_replace("\n", ' / ', $out)) . ')');
reset_dir($dir);
setup_disk($settings, [rec('bob', 'IDA', $rp, ['uid' => '2000']), rec('bob', 'IDB', 'old.example', ['uid' => '2000'])]);
check(!webauthn_delete_credential('IDA', 'bob', false, $err) && str_contains((string)$err, 'last usable'),
    'R4-I a passkey for another RP ID does not count as one left');
check(webauthn_delete_credential('IDA', 'bob', true, $err), 'R4-I with a verified session (or as admin) the last one may go');

/* ---- R4-J: LDAP names that pfSense authenticates as another account ---- */
reset_dir($dir);
setup_disk($settings, [], ['system' => ['authserver' => [['name' => 'corp', 'type' => 'ldap']]]]);
$ldap = ['authsource' => 'LDAP/corp', 'remoteauth' => true];
check(!webauthn_registrable_name(['Username' => 'x\\carol'] + $ldap), 'R4-J "x\\carol" (authenticated as x) cannot hold passkeys');
check(webauthn_registrable_name(['Username' => 'carol'] + $ldap) && webauthn_registrable_name(['Username' => 'alice@corp'] + $ldap),
    'R4-J plain and @domain names can');
check(!webauthn_registrable_name(['Username' => "eve\x01"] + $ldap) && !webauthn_registrable_name(['Username' => "eve\u{202E}x"] + $ldap),
    'R4-J names with control or format characters cannot');
check(!webauthn_registrable_name(['Username' => 'x/carol'] + $ldap) && !webauthn_registrable_name(['Username' => 'x\\carol', 'authsource' => 'RADIUS/r']) &&
    !webauthn_registrable_name(['Username' => 'x/carol', 'authsource' => 'RADIUS/r']), 'R4-J ...nor "\\" or "/" names through LDAP or RADIUS');
check(webauthn_registrable_name(['Username' => 'carol@realm', 'authsource' => 'RADIUS/r']), 'R4-J RADIUS user@realm names can');
setup_disk($settings, [], ['system' => ['authserver' => [['name' => 'corp', 'type' => 'ldap', 'ldap_nostrip_at' => '']]]]);
check(webauthn_ldap_account(['Username' => 'alice@corp'] + $ldap) === 'alice@corp', 'R4-J ldap_nostrip_at respected');
/* N2: with ldap_nostrip_at, "@" names can register. */
check(webauthn_registrable_name(['Username' => 'carol@corp.com'] + $ldap), 'N2 nostrip: "carol@corp.com" can register');
check(webauthn_add_credential('carol@corp.com', 'k', make_reg($rp), $rp) === null, 'N2 setup: registered');
check(webauthn_session_status($settings, ['Username' => 'CAROL@corp.com'] + $ldap, $tunnel) === 'require',
    'N2 a case variant of the name needs its passkey');
/* C1: every spelling the backend may take for the owner still needs the passkey (Enforce off). */
$off = array_merge($settings, ['enforce' => '']);
setup_disk($off, [], ['system' => ['authserver' => [['name' => 'corp', 'type' => 'ldap']]]]);
foreach (['carol@x%y' => ['carol', 'Carol@other'], 'carol%ops' => ['carol%ops@corp']] as $owner => $logins) {
	webauthn_add_credential($owner, 'k', make_reg($rp), $rp);
	foreach ($logins as $login) {
		$st = webauthn_session_status($off, ['Username' => $login] + $ldap, $tunnel);
		check($st === 'require', "C1 owner '$owner', sign-in '$login': passkey step not skipped (got $st)");
	}
}

/* ---- R4-K: the used-challenge list cannot be filled by one account ---- */
reset_dir($dir);
setup_disk($settings, []);
$_COOKIE = [];
$ok = 0;
for ($i = 0; $i < WEBAUTHN_MAX_LIVE_NONCES_PER_USER + 5; $i++) {
	$c = webauthn_new_challenge('register', 'mallory');
	if (webauthn_use_challenge('register', 'mallory', json_encode(['challenge' => webauthn_b64url_encode($c)]), function ($ch) { return 1; }) !== null) {
		$ok++;
	}
}
check($ok === WEBAUTHN_MAX_LIVE_NONCES_PER_USER, "R4-K one account completes at most the per-user limit ($ok)");
$c = webauthn_new_challenge('login', 'admin');
check(webauthn_use_challenge('login', 'admin', json_encode(['challenge' => webauthn_b64url_encode($c)]), function ($ch) { return 1; }) === 1,
    'R4-K other accounts still sign in');
file_put_contents(WEBAUTHN_USED_FILE, json_encode([bin2hex(random_bytes(16)) => time() + 100]));
$c = webauthn_new_challenge('login', 'admin');
check(webauthn_use_challenge('login', 'admin', json_encode(['challenge' => webauthn_b64url_encode($c)]), function ($ch) { return 1; }) === 1,
    'R4-K entries in the old format (bare expiry) still read');
reset_dir($dir);
setup_disk($settings, []);
$reg = make_reg($rp);
check(webauthn_add_credential('bob', 'k', $reg, $rp) === null, 'setup: passkey registered');
$c = webauthn_new_challenge('register', 'bob');
$cdj = json_encode(['challenge' => webauthn_b64url_encode($c)]);
try {
	webauthn_use_challenge('register', 'bob', $cdj, function ($ch) use ($reg, $rp) {
		$e = webauthn_add_credential('bob', 'k', $reg, $rp);
		if ($e !== null) {
			throw new WebAuthnException($e);
		}
		return $reg;
	});
} catch (WebAuthnException $e) {
}
check(webauthn_use_challenge('register', 'bob', $cdj, function ($ch) { return 'fresh'; }) === 'fresh',
    'R4-K a ceremony that fails inside the check does not use up its challenge');
/* N1: the page saves the passkey after the challenge check, not while holding the lock every sign-in needs. */
$page = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/system_webauthn.php');
$use = strpos($page, "webauthn_use_challenge('register'");
$end = strpos($page, '});', $use);
$add = strpos($page, 'webauthn_add_credential(', $use);
check($use !== false && $add > $end, 'N1 registration saves outside the used-challenge lock');
reset_dir($dir);
setup_disk($settings, []);
for ($i = 0; $i < WEBAUTHN_MAX_CREDENTIALS_PER_USER; $i++) {
	webauthn_add_credential('bob', "k$i", make_reg($rp), $rp);
}
check(count(webauthn_get_credentials('bob')) === WEBAUTHN_MAX_CREDENTIALS_PER_USER && webauthn_add_credential('bob', 'one more', make_reg($rp), $rp) !== null,
    'R4-K at most ' . WEBAUTHN_MAX_CREDENTIALS_PER_USER . ' passkeys per account');
reset_dir($dir);
$orphans = [];
for ($i = 0; $i < WEBAUTHN_MAX_CREDENTIALS_PER_USER; $i++) {
	$orphans[] = rec('bob', "O$i", $rp, ['uid' => '1999']);   /* of a deleted account "bob" */
}
setup_disk($settings, $orphans);
check(webauthn_add_credential('bob', 'new', make_reg($rp), $rp, '2000') === null, 'R4-K passkeys of a deleted account do not count towards the limit');

/* ---- R4-L: revocation lifted and set under the same lock ---- */
$src = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/webauthn/storage.inc');
$add = substr($src, strpos($src, 'function webauthn_add_credential'), 4000);
check(preg_match('/,\s*function \(\) use \(\$id, &\$error\) \{.*?webauthn_unrevoke\(\$id\)/s', $add) === 1,
    'R4-L the revocation is lifted in the after-save step, inside the config lock');

/* ---- R4-M: changes made outside the WebAuthn page are reported ---- */
reset_dir($dir);
setup_disk($settings, []);
@unlink("$dir/notices.log");
check(!webauthn_check_config_state(), 'R4-M first look records the state silently');
check(!webauthn_check_config_state(), 'R4-M unchanged state: nothing reported');
webauthn_save_settings($settings);
check(!webauthn_check_config_state(), 'R4-M a change by this package is not reported');
$GLOBALS['test_config']['installedpackages']['webauthn']['config'][0]['enable'] = '';   /* another page saves an older copy */
write_config('other page');
check(webauthn_check_config_state() && str_contains((string)@file_get_contents("$dir/notices.log"), 'changed outside'),
    'R4-M a stale save switching the second factor off raises a notice');
check(!webauthn_check_config_state(), 'R4-M ...once');
/* N4: a request that loaded the config before this package's last save is not an outside change. */
reset_dir($dir);
setup_disk($settings, []);
webauthn_check_config_state();
$stale = $GLOBALS['test_config'];
webauthn_add_credential('bob', 'k', make_reg($rp), $rp);        /* another request saves a passkey */
$GLOBALS['test_config'] = $stale;                                 /* this request still has the older copy */
@unlink("$dir/notices.log");
function parse_xml_config($file, $root) {
	$GLOBALS['parses'] = ($GLOBALS['parses'] ?? 0) + 1;
	return unserialize(file_get_contents(RACE_DISK));
}
function g_get($k) {
	return ['conf_path' => '/cf/conf', 'xml_rootobj' => 'pfsense'][$k];
}
check(!webauthn_check_config_state() && !file_exists("$dir/notices.log"), 'N4 an older copy in memory after a save by this package: no alarm');
check(webauthn_config_hash(['item' => [], 'config' => [['enable' => '']]]) === webauthn_config_hash(['config' => [['enable' => '']]]) &&
    webauthn_config_hash(['x' => 1]) === webauthn_config_hash(['x' => '1']), 'N4 hash ignores empty lists and value types (as config.xml stores them)');
/* N3/C2: with /conf full (state and notice files unwritable), no notice storm and no parse per request. */
$GLOBALS['test_config']['installedpackages']['webauthn']['config'][0]['enforce'] = '';
write_config('outside change');
@mkdir(WEBAUTHN_STATE_FILE . '.' . getmypid() . '.tmp');
@mkdir(WEBAUTHN_NOTICE_FILE . '.' . getmypid() . '.tmp');
$GLOBALS['parses'] = 0;
for ($i = 0; $i < 10; $i++) {
	webauthn_check_config_state();
}
@rmdir(WEBAUTHN_STATE_FILE . '.' . getmypid() . '.tmp');
@rmdir(WEBAUTHN_NOTICE_FILE . '.' . getmypid() . '.tmp');
check(substr_count((string)@file_get_contents("$dir/notices.log"), 'changed outside') === 1, 'C2 full /conf: one notice in 10 requests');
check($GLOBALS['parses'] === 1, "C2 full /conf: config.xml parsed once, not on every request ({$GLOBALS['parses']})");
$gate = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/webauthn/gate.inc');
check(strpos($gate, 'webauthn_check_config_state();') < strpos($gate, "if (empty(\$settings['enable']))"),
    'R4-M the gate checks before it looks at the enable setting');

reset_dir($dir);
@rmdir($dir);
echo "$count checks, $failures failed\n";
exit($failures ? 1 : 0);
