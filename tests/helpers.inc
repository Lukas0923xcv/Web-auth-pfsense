<?php
/* Test helpers: a CBOR encoder and a software authenticator. */

/* ---- Minimal CBOR encoder for building authenticator responses ---- */
function cbor_head($major, $n) {
	if ($n < 24) return chr(($major << 5) | $n);
	if ($n < 256) return chr(($major << 5) | 24) . chr($n);
	if ($n < 65536) return chr(($major << 5) | 25) . pack('n', $n);
	return chr(($major << 5) | 26) . pack('N', $n);
}
function cbor_enc($v) {
	if ($v instanceof WebAuthnCborBytes) return cbor_head(2, strlen($v->bytes)) . $v->bytes;
	if (is_int($v)) return $v >= 0 ? cbor_head(0, $v) : cbor_head(1, -1 - $v);
	if (is_string($v)) return cbor_head(3, strlen($v)) . $v;
	if (is_array($v) && array_is_list($v) && !isset($v['__map'])) {
		$o = cbor_head(4, count($v));
		foreach ($v as $x) $o .= cbor_enc($x);
		return $o;
	}
	unset($v['__map']);
	$o = cbor_head(5, count($v));
	foreach ($v as $k => $x) $o .= cbor_enc($k) . cbor_enc($x);
	return $o;
}
function b($s) { return new WebAuthnCborBytes($s); }

/* ---- Fake authenticator ---- */
class FakeAuthenticator {
	public $priv, $cose, $alg, $id, $count = 0, $sodium;
	function __construct($alg) {
		$this->alg = $alg;
		$this->id = random_bytes(16);
		if ($alg == WEBAUTHN_ALG_ES256) {
			$this->priv = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
			$d = openssl_pkey_get_details($this->priv)['ec'];
			$this->cose = ['__map' => 1, 1 => 2, 3 => -7, -1 => 1,
			    -2 => b(str_pad($d['x'], 32, "\0", STR_PAD_LEFT)), -3 => b(str_pad($d['y'], 32, "\0", STR_PAD_LEFT))];
		} elseif ($alg == WEBAUTHN_ALG_RS256) {
			$this->priv = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
			$d = openssl_pkey_get_details($this->priv)['rsa'];
			$this->cose = ['__map' => 1, 1 => 3, 3 => -257, -1 => b($d['n']), -2 => b($d['e'])];
		} else {
			$this->sodium = sodium_crypto_sign_keypair();
			$this->cose = ['__map' => 1, 1 => 1, 3 => -8, -1 => 6, -2 => b(sodium_crypto_sign_publickey($this->sodium))];
		}
	}
	function toState() {
		return fake_authenticator_state($this);
	}
	static function fromState(array $s) {
		$a = new FakeAuthenticator(WEBAUTHN_ALG_ES256);
		$a->priv = openssl_pkey_get_private($s['pem']);
		$a->cose = $s['cose'];
		$a->id = $s['id'];
		$a->count = $s['count'];
		return $a;
	}
	function authData($rp_id, $flags, $attested) {
		$ad = hash('sha256', $rp_id, true) . chr($flags | ($attested ? WEBAUTHN_FLAG_AT : 0)) . pack('N', $this->count);
		if ($attested) {
			$ad .= str_repeat("\0", 16) . pack('n', strlen($this->id)) . $this->id . cbor_enc($this->cose);
		}
		return $ad;
	}
	function clientData($type, $challenge, $origin) {
		return json_encode(['type' => $type, 'challenge' => webauthn_b64url_encode($challenge), 'origin' => $origin, 'crossOrigin' => false]);
	}
	function create($challenge, $rp_id, $origin, $flags = 0x05) {
		$cd = $this->clientData('webauthn.create', $challenge, $origin);
		$att = cbor_enc(['__map' => 1, 'fmt' => 'none', 'attStmt' => ['__map' => 1], 'authData' => b($this->authData($rp_id, $flags, true))]);
		return [$cd, $att];
	}
	function get($challenge, $rp_id, $origin, $flags = 0x05, $bump = true) {
		if ($bump) $this->count++;
		$cd = $this->clientData('webauthn.get', $challenge, $origin);
		$ad = $this->authData($rp_id, $flags, false);
		$msg = $ad . hash('sha256', $cd, true);
		if ($this->alg == WEBAUTHN_ALG_EDDSA) {
			$sig = sodium_crypto_sign_detached($msg, sodium_crypto_sign_secretkey($this->sodium));
		} else {
			openssl_sign($msg, $sig, $this->priv, OPENSSL_ALGO_SHA256);
		}
		return [$cd, $ad, $sig];
	}
}

/* ES256 authenticators can be persisted between test processes. */
function fake_authenticator_state(FakeAuthenticator $a): array {
	openssl_pkey_export($a->priv, $pem);
	return ['pem' => $pem, 'cose' => $a->cose, 'id' => $a->id, 'count' => $a->count];
}
