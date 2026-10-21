<?php
/* Mutation fuzz of the CBOR / authenticator-data / COSE parsers. Any
 * exception other than WebAuthn(Cbor)Exception, or any PHP warning, is
 * reported. php tests/review3/fuzz_parsers.php [iterations] */
require_once(dirname(__DIR__, 2) . '/src/usr/local/pkg/webauthn/webauthn_lib.inc');
require_once(dirname(__DIR__) . '/helpers.inc');
set_error_handler(function ($no, $str, $file, $line) { throw new ErrorException($str, 0, $no, $file, $line); });
$n = (int)($argv[1] ?? 20000);
$rp = 'example.com';
$seeds = [];
foreach ([WEBAUTHN_ALG_ES256, WEBAUTHN_ALG_RS256, WEBAUTHN_ALG_EDDSA] as $alg) {
	$a = new FakeAuthenticator($alg);
	[, $att] = $a->create(random_bytes(32), $rp, 'https://example.com');
	$seeds[] = $att;
}
$bad = 0;
for ($i = 0; $i < $n; $i++) {
	$s = $seeds[$i % 3];
	$m = mt_rand(1, 6);
	for ($j = 0; $j < $m; $j++) {
		$p = mt_rand(0, strlen($s) - 1);
		switch (mt_rand(0, 3)) {
		case 0: $s[$p] = chr(mt_rand(0, 255)); break;
		case 1: $s = substr($s, 0, $p); break;
		case 2: $s = substr($s, 0, $p) . chr(mt_rand(0, 255)) . substr($s, $p); break;
		case 3: $s[$p] = chr(ord($s[$p]) ^ (1 << mt_rand(0, 7))); break;
		}
		if ($s === '') { $s = "\xa0"; }
	}
	try {
		$att = webauthn_cbor_decode($s);
		if (is_array($att) && isset($att['authData']) && $att['authData'] instanceof WebAuthnCborBytes) {
			$ad = webauthn_parse_auth_data($att['authData']->bytes);
			if (isset($ad['credential_public_key']) && is_array($ad['credential_public_key'])) {
				webauthn_cose_to_pem($ad['credential_public_key']);
			}
		}
	} catch (WebAuthnException | WebAuthnCborException $e) {
	} catch (Throwable $e) {
		$bad++;
		if ($bad <= 5) {
			echo 'UNEXPECTED ' . get_class($e) . ': ' . $e->getMessage() . ' @' . basename($e->getFile()) . ':' . $e->getLine() . ' input=' . bin2hex($s) . "\n";
		}
	}
}
echo "$n inputs, $bad unexpected\n";
exit($bad ? 1 : 0);
