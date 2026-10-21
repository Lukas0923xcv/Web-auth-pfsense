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

/**
 * Decode one CBOR item from $data starting at $offset.
 * Returns the decoded value; $offset is advanced past the item.
 * Byte strings are returned as WebAuthnCborBytes so they can be told
 * apart from text strings.
 * Long: one switch over the eight CBOR major types, each a few lines;
 * spreading it over functions would hide the format's structure.
 * @return mixed
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
	} elseif ($info <= 27) {
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
			$k = webauthn_cbor_map_key($k);
			if (array_key_exists($k, $out)) {
				throw new WebAuthnCborException('CBOR duplicate map key');
			}
			$out[$k] = webauthn_cbor_decode_item($data, $offset, $depth + 1);
		}
		return $out;
	case 6:
		/* Tag: ignore the tag number and return the tagged item. */
		return webauthn_cbor_decode_item($data, $offset, $depth + 1);
	default:
		/* Major type 7: simple values. */
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
}

/*
 * PHP converts array keys like "1" to the integer 1, which would let a
 * text key stand in for (or collide with) an integer key such as the
 * COSE labels. Text keys that PHP would convert are prefixed so integer
 * and text keys stay distinct; other text keys are kept as they are.
 */
define('WEBAUTHN_CBOR_TEXT_KEY_PREFIX', "\0text:");

function webauthn_cbor_map_key(int|string $k): int|string {
	/* PHP's rule: a decimal integer string in canonical form becomes an int key. */
	if (is_string($k) && (string)(int)$k === $k) {
		return WEBAUTHN_CBOR_TEXT_KEY_PREFIX . $k;
	}
	return $k;
}

/**
 * Decode a buffer that must contain exactly one CBOR item.
 * @return mixed
 */
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
