<?php
/*
 * cbor.inc
 *
 * Minimal CBOR (RFC 8949) decoder covering what WebAuthn needs:
 * definite-length integers, byte/text strings, arrays, maps, tags
 * (skipped), and simple values. Indefinite lengths and floats are
 * rejected, since authenticators do not emit them in the structures
 * parsed here.
 *
 * Licensed under the Apache License, Version 2.0.
 */

class WebAuthnCborException extends Exception {}

/*
 * Decode one CBOR item from $data starting at $offset.
 * Returns the decoded value; $offset is advanced past the item.
 * Byte strings are returned as WebAuthnCborBytes so they can be told
 * apart from text strings.
 */
function webauthn_cbor_decode_item(string $data, int &$offset, int $depth = 0) {
	if ($depth > 16) {
		throw new WebAuthnCborException('CBOR nesting too deep');
	}
	$len = strlen($data);
	if ($offset >= $len) {
		throw new WebAuthnCborException('CBOR truncated');
	}
	$ib = ord($data[$offset++]);
	$major = $ib >> 5;
	$info = $ib & 0x1f;

	if ($info < 24) {
		$arg = $info;
	} elseif ($info >= 24 && $info <= 27) {
		$n = 1 << ($info - 24);
		if ($offset + $n > $len) {
			throw new WebAuthnCborException('CBOR truncated');
		}
		$arg = 0;
		for ($i = 0; $i < $n; $i++) {
			$arg = ($arg << 8) | ord($data[$offset + $i]);
		}
		if ($n == 8 && $arg < 0) {
			throw new WebAuthnCborException('CBOR integer out of range');
		}
		$offset += $n;
	} else {
		throw new WebAuthnCborException('CBOR indefinite length or reserved value not supported');
	}

	switch ($major) {
	case 0:
		return $arg;
	case 1:
		return -1 - $arg;
	case 2:
	case 3:
		if ($offset + $arg > $len) {
			throw new WebAuthnCborException('CBOR string truncated');
		}
		$s = substr($data, $offset, $arg);
		$offset += $arg;
		return ($major == 2) ? new WebAuthnCborBytes($s) : $s;
	case 4:
		$out = [];
		for ($i = 0; $i < $arg; $i++) {
			$out[] = webauthn_cbor_decode_item($data, $offset, $depth + 1);
		}
		return $out;
	case 5:
		$out = [];
		for ($i = 0; $i < $arg; $i++) {
			$k = webauthn_cbor_decode_item($data, $offset, $depth + 1);
			if (!is_int($k) && !is_string($k)) {
				throw new WebAuthnCborException('CBOR map key type not supported');
			}
			if (array_key_exists($k, $out)) {
				throw new WebAuthnCborException('CBOR duplicate map key');
			}
			$out[$k] = webauthn_cbor_decode_item($data, $offset, $depth + 1);
		}
		return $out;
	case 6:
		/* Tag: ignore the tag number and return the tagged item. */
		return webauthn_cbor_decode_item($data, $offset, $depth + 1);
	case 7:
		switch ($info) {
		case 20:
			return false;
		case 21:
			return true;
		case 22:
		case 23:
			return null;
		}
		throw new WebAuthnCborException('CBOR floats/simple values not supported');
	}
	throw new WebAuthnCborException('CBOR invalid major type');
}

/* Decode a buffer that must contain exactly one CBOR item. */
function webauthn_cbor_decode(string $data) {
	$offset = 0;
	$value = webauthn_cbor_decode_item($data, $offset);
	if ($offset != strlen($data)) {
		throw new WebAuthnCborException('CBOR trailing data');
	}
	return $value;
}

class WebAuthnCborBytes {
	public function __construct(public string $bytes) {}
}
