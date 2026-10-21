<?php
/*
 * Real authenticator responses, and one negative test per verification
 * step of WebAuthn Level 3 §7.1 (registration) and §7.2 (sign-in):
 *   php tests/webauthn_vectors_test.php
 *
 * The vectors come from py_webauthn's test suite (BSD-3-Clause, see
 * tests/fixtures/vectors/README.md). Each negative test changes one field
 * of a valid response and checks that the step meant to catch it does:
 * the expected error message names that step.
 */
require_once(dirname(__DIR__) . '/src/usr/local/pkg/webauthn/webauthn_lib.inc');
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
function throws(callable $f, $name, $needle) {
	try {
		$f();
		check(false, "$name (no exception)");
	} catch (WebAuthnException $e) {
		check(str_contains($e->getMessage(), $needle), "$name (got: {$e->getMessage()})");
	}
}
function d($s) {
	return webauthn_b64url_decode($s);
}

$vectors = json_decode(file_get_contents(__DIR__ . '/fixtures/vectors/py_webauthn.json'), true);
$alg_names = [WEBAUTHN_ALG_ES256 => 'ES256', WEBAUTHN_ALG_RS256 => 'RS256', WEBAUTHN_ALG_EDDSA => 'EdDSA'];

/* ---- Real registrations ---- */
$seen = [];
foreach ($vectors['registration'] as $v) {
	try {
		$r = webauthn_verify_registration(d($v['clientDataJSON']), d($v['attestationObject']), d($v['challenge']),
		    $v['rp_id'], [$v['origin']], false);
		check($r['credential_id'] === d($v['credential_id']), "registration {$v['source']}: credential ID");
		$seen[$r['alg']] = true;
	} catch (WebAuthnException $e) {
		check(false, "registration {$v['source']}: " . $e->getMessage());
	}
}
foreach ($alg_names as $alg => $name) {
	check(isset($seen[$alg]), "a real $name registration is among the vectors");
}

/* ---- Real sign-ins ---- */
$stored = [];
$seen = [];
foreach ($vectors['authentication'] as $v) {
	$key = webauthn_cose_to_pem(webauthn_cbor_decode(d($v['credential_public_key'])));
	$cred = ['alg' => $key['alg'], 'pem' => $key['pem'], 'sign_count' => $v['sign_count']];
	$stored[$alg_names[$key['alg']]] = [$cred, $v];
	try {
		$n = webauthn_verify_assertion($cred, d($v['clientDataJSON']), d($v['authenticatorData']), d($v['signature']),
		    d($v['challenge']), $v['rp_id'], [$v['origin']], $v['require_uv'], $info);
		check($n === $v['new_sign_count'], "sign-in {$v['source']}: new counter {$v['new_sign_count']}");
		$seen[$key['alg']] = true;
	} catch (WebAuthnException $e) {
		check(false, "sign-in {$v['source']}: " . $e->getMessage());
	}
}
foreach ($alg_names as $alg => $name) {
	check(isset($seen[$alg]), "a real $name sign-in is among the vectors");
}

/* ---- §7.1 registration: one changed field per step ---- */
$v = $vectors['registration'][0];
$cd = d($v['clientDataJSON']);
$att = d($v['attestationObject']);
$ch = d($v['challenge']);
$rp = $v['rp_id'];
$origin = $v['origin'];
$reg = function ($cd, $att, $uv = false, $rp_id = null, $origins = null) use ($ch, $rp, $origin) {
	return webauthn_verify_registration($cd, $att, $ch, $rp_id ?? $rp, $origins ?? [$origin], $uv);
};
/* clientDataJSON with one member changed. */
$cd_with = function (string $json, array $change): string {
	return json_encode(array_merge(json_decode($json, true), $change));
};
/* attestationObject with its authenticator data replaced. */
$att_with = function (string $att, callable $change): string {
	$o = webauthn_cbor_decode($att);
	return cbor_enc(['__map' => 1, 'fmt' => $o['fmt'], 'attStmt' => ['__map' => 1], 'authData' => b($change($o['authData']->bytes))]);
};
$flags = function (string $ad, int $set, int $clear = 0): string {
	$ad[32] = chr((ord($ad[32]) | $set) & ~$clear);
	return $ad;
};

throws(fn() => $reg('not json', $att), '7.1 step 6: clientDataJSON must be JSON', 'not valid JSON');
throws(fn() => $reg($cd_with($cd, ['type' => 'webauthn.get']), $att), '7.1 step 7: type must be webauthn.create', 'ceremony type');
throws(fn() => $reg($cd_with($cd, ['challenge' => webauthn_b64url_encode(random_bytes(32))]), $att), '7.1 step 8: challenge', 'Challenge');
throws(fn() => $reg($cd_with($cd, ['origin' => 'https://evil.example']), $att), '7.1 step 9: origin', 'Origin');
throws(fn() => $reg($cd_with($cd, ['crossOrigin' => true]), $att), '7.1 step 10: crossOrigin / topOrigin', 'Cross-origin');
throws(fn() => $reg($cd, "\xa1\x63fmt\x64none"), '7.1 step 12: attestationObject must hold authData', 'no authData');
throws(fn() => $reg($cd, substr($att, 0, -3)), '7.1 step 12: attestationObject must decode', 'Invalid attestationObject');
throws(fn() => $reg($cd, $att, false, 'example.org'), '7.1 step 13: rpIdHash', 'RP ID hash');
throws(fn() => $reg($cd, $att_with($att, fn($ad) => $flags($ad, 0, WEBAUTHN_FLAG_UP))), '7.1 step 14: UP must be set', 'User presence');
throws(fn() => $reg($cd, $att_with($att, fn($ad) => $flags($ad, 0, WEBAUTHN_FLAG_UV)), true), '7.1 step 15: UV when required', 'User verification');
throws(fn() => $reg($cd, $att_with($att, fn($ad) => $flags($ad, WEBAUTHN_FLAG_BS, WEBAUTHN_FLAG_BE))), '7.1 step 16-17: BS without BE', 'Backup state');
throws(fn() => $reg($cd, $att_with($att, fn($ad) => substr($flags($ad, 0, WEBAUTHN_FLAG_AT), 0, 37))), '7.1 step 18: attested credential data present', 'No attested credential data');
throws(fn() => $reg($cd, $att_with($att, fn($ad) => $ad . "\x00")), '7.1 step 18: authenticator data has no trailing bytes', 'Trailing bytes');
throws(fn() => $reg($cd, $att_with($att, fn($ad) => $flags($ad, WEBAUTHN_FLAG_ED))), '7.1 step 18: extension data must be valid CBOR', 'extension data');
/* Steps 19-20 and 26 (alg among pubKeyCredParams, key parameters, credential ID length) need a newly made authenticator. */
$fa = new FakeAuthenticator(WEBAUTHN_ALG_ES256);
$fch = random_bytes(32);
$freg = function ($fa) use ($fch) {
	[$c, $a] = $fa->create($fch, 'pfsense.example.com', 'https://pfsense.example.com');
	return webauthn_verify_registration($c, $a, $fch, 'pfsense.example.com', ['https://pfsense.example.com'], false);
};
$fa->cose[3] = -35;
throws(fn() => $freg($fa), '7.1 step 20: alg must be one of pubKeyCredParams', 'Unsupported credential algorithm');
$fa = new FakeAuthenticator(WEBAUTHN_ALG_ES256);
$fa->cose[-1] = 2;
throws(fn() => $freg($fa), '7.1 step 20: ES256 key must be on P-256', 'P-256');
$fa = new FakeAuthenticator(WEBAUTHN_ALG_EDDSA);
$fa->cose[-1] = 7;
throws(fn() => $freg($fa), '7.1 step 20: EdDSA key must be Ed25519', 'Ed25519');
$fa = new FakeAuthenticator(WEBAUTHN_ALG_RS256);
$fa->cose[-1] = b(random_bytes(128));
throws(fn() => $freg($fa), '7.1 step 20: RSA key of at least 2048 bits', '2048');
$fa = new FakeAuthenticator(WEBAUTHN_ALG_ES256);
$fa->id = random_bytes(1024);
throws(fn() => $freg($fa), '7.1 step 26: credential ID at most 1023 bytes', 'credential ID length');
/*
 * Not checked in this file, by design or elsewhere:
 * - steps 21-24 (attestation statement): credentials are created with
 *   attestation "none", so the statement is not verified (§7.1 allows
 *   this; see the header of webauthn_lib.inc);
 * - step 27 (credential ID not registered yet): webauthn_add_credential(),
 *   tested in tests/storage_and_sessions_test.php ("an ID that is
 *   already registered is refused").
 */

/* ---- §7.2 sign-in: one changed field per step ---- */
[$cred, $v] = $stored['ES256'];
$cd = d($v['clientDataJSON']);
$ad = d($v['authenticatorData']);
$sig = d($v['signature']);
$ch = d($v['challenge']);
$get = function ($cd, $ad, $sig, $uv = false, $cred_override = null, $rp_id = null) use ($cred, $ch, $v) {
	return webauthn_verify_assertion($cred_override ?? $cred, $cd, $ad, $sig, $ch, $rp_id ?? $v['rp_id'], [$v['origin']], $uv);
};
throws(fn() => $get('{', $ad, $sig), '7.2 step 10: clientDataJSON must be JSON', 'not valid JSON');
throws(fn() => $get($cd_with($cd, ['type' => 'webauthn.create']), $ad, $sig), '7.2 step 11: type must be webauthn.get', 'ceremony type');
throws(fn() => $get($cd_with($cd, ['challenge' => webauthn_b64url_encode(random_bytes(32))]), $ad, $sig), '7.2 step 12: challenge', 'Challenge');
throws(fn() => $get($cd_with($cd, ['origin' => 'https://evil.example']), $ad, $sig), '7.2 step 13: origin', 'Origin');
throws(fn() => $get($cd_with($cd, ['crossOrigin' => true]), $ad, $sig), '7.2 step 14: crossOrigin / topOrigin', 'Cross-origin');
throws(fn() => $get($cd, substr($ad, 0, 36), $sig), '7.2 step 15: authenticator data must parse', 'too short');
throws(fn() => $get($cd, $ad, $sig, false, null, 'example.org'), '7.2 step 15: rpIdHash', 'RP ID hash');
throws(fn() => $get($cd, $flags($ad, 0, WEBAUTHN_FLAG_UP), $sig), '7.2 step 16: UP must be set', 'User presence');
throws(fn() => $get($cd, $ad, $sig, true), '7.2 step 17: UV when required', 'User verification');
throws(fn() => $get($cd, $flags($ad, WEBAUTHN_FLAG_BS, WEBAUTHN_FLAG_BE), $sig), '7.2 step 18: BS without BE', 'Backup state');
$bad = $sig;
$bad[20] = chr(ord($bad[20]) ^ 1);
throws(fn() => $get($cd, $ad, $bad), '7.2 step 21: signature over authData || hash(clientDataJSON)', 'Signature verification');
throws(fn() => $get($cd, $flags($ad, WEBAUTHN_FLAG_UV), $sig), '7.2 step 21: signed authenticator data cannot change', 'Signature verification');
throws(fn() => $get($cd, $ad, $sig, false, $stored['EdDSA'][0]), '7.2 step 21: another credential\'s key does not verify', 'Signature verification');
throws(fn() => $get($cd, $ad, $sig, false, ['sign_count' => $v['new_sign_count']] + $cred), '7.2 step 22: signature counter must increase', 'counter');
/* The stored algorithm must match the stored key: the same valid ES256
 * response is refused when its record says RS256 or EdDSA. */
throws(fn() => $get($cd, $ad, $sig, false, ['alg' => WEBAUTHN_ALG_RS256] + $cred), '7.2 step 21: stored RS256 with an EC key refused', 'Signature verification');
throws(fn() => $get($cd, $ad, $sig, false, ['alg' => WEBAUTHN_ALG_EDDSA] + $cred), '7.2 step 21: stored EdDSA with an EC key refused', 'Signature verification');
[$rsa, $rv] = $stored['RS256'];
throws(fn() => webauthn_verify_assertion(['alg' => WEBAUTHN_ALG_ES256] + $rsa, d($rv['clientDataJSON']), d($rv['authenticatorData']),
    d($rv['signature']), d($rv['challenge']), $rv['rp_id'], [$rv['origin']], false), '7.2 step 21: stored ES256 with an RSA key refused', 'Signature verification');
/*
 * Steps 5-6 (the credential is one of allowCredentials and belongs to the
 * signed-in user) are checked by webauthn_find_credential() in the gate:
 * tests/gate_flow_test.php and tests/gate_ldap_and_revocation_test.php.
 */

echo "$count checks, $failures failed\n";
exit($failures ? 1 : 0);
