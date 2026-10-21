<?php
/*
 * challenge.inc
 *
 * WebAuthn challenges: creation, verification and single use.
 *
 * Licensed under the Apache License, Version 2.0.
 */

/* Loaded by webauthn.inc, which defines the constants used here. */

/*
 * Challenges are self-contained: random nonce, expiry, and an HMAC that
 * binds them to the PHP session, the user, and the purpose. They are not
 * stored in the session, so loading the page again (another tab, a
 * prefetch, a password manager fetching the page) cannot invalidate a
 * challenge the browser is already using. Each nonce is accepted once.
 *
 *   challenge = nonce(16) || expiry(4, big endian) || hmac(16)
 */
function webauthn_hmac_key(): string {
	$key = @file_get_contents(WEBAUTHN_KEY_FILE);
	if ($key !== false && strlen($key) == 32) {
		return $key;
	}
	/* Create the key through a temp file, so no request ever reads a
	 * half-written key and replaces it. The first writer wins. */
	$key = random_bytes(32);
	$tmp = WEBAUTHN_KEY_FILE . '.' . getmypid() . '.tmp';
	$old = umask(077);
	if (@file_put_contents($tmp, $key) === 32 && !@link($tmp, WEBAUTHN_KEY_FILE)) {
		$existing = @file_get_contents(WEBAUTHN_KEY_FILE);
		if ($existing !== false && strlen($existing) == 32) {
			$key = $existing;
		} else {
			@rename($tmp, WEBAUTHN_KEY_FILE);
		}
	}
	@unlink($tmp);
	umask($old);
	return $key;
}

function webauthn_challenge_mac(string $purpose, string $username, string $payload): string {
	$data = implode("\0", [$purpose, webauthn_session_sid(), webauthn_normalize_username($username), $payload]);
	return substr(hash_hmac('sha256', $data, webauthn_hmac_key(), true), 0, 16);
}

function webauthn_new_challenge(string $purpose, string $username): string {
	$payload = random_bytes(16) . pack('N', time() + WEBAUTHN_CHALLENGE_TTL);
	return $payload . webauthn_challenge_mac($purpose, $username, $payload);
}

/**
 * Check the challenge the browser signed (taken from clientDataJSON):
 * HMAC for this session, user and purpose, and expiry. Returns
 * [challenge, nonce, expires] or null. A challenge expiring further ahead
 * than a fresh one would (the clock went back) is refused too.
 * @return array{0: string, 1: string, 2: int}|null
 */
function webauthn_parse_challenge(string $purpose, string $username, string $client_data_json, int $now): ?array {
	$cd = json_decode($client_data_json, true);
	try {
		$challenge = webauthn_b64url_decode((string)($cd['challenge'] ?? ''));
	} catch (WebAuthnException $e) {
		return null;
	}
	if (strlen($challenge) != 36) {
		return null;
	}
	$payload = substr($challenge, 0, 20);
	if (!hash_equals(webauthn_challenge_mac($purpose, $username, $payload), substr($challenge, 20))) {
		return null;
	}
	$expires = unpack('N', substr($payload, 16, 4))[1];
	if ($expires < $now || $expires > $now + WEBAUTHN_CHALLENGE_TTL) {
		return null;
	}
	return [$challenge, bin2hex(substr($payload, 0, 16)), $expires];
}

/**
 * Run $verify($challenge) for the challenge in clientDataJSON while
 * holding the used-challenge lock, and record the challenge as used only
 * if $verify returns (an exception aborts without recording it). So only
 * completed ceremonies fill the list, which an attacker without a passkey
 * therefore cannot fill, and one signed response is never accepted twice,
 * not even by two parallel requests. Returns $verify's result, or null if
 * the challenge is forged, expired, for another session/user/purpose,
 * already used, or its use cannot be recorded (fail closed).
 * @return mixed
 */
function webauthn_use_challenge(string $purpose, string $username, string $client_data_json, callable $verify) {
	$now = time();
	$parsed = webauthn_parse_challenge($purpose, $username, $client_data_json, $now);
	if ($parsed === null) {
		return null;
	}
	[$challenge, $nonce, $expires] = $parsed;
	$who = substr(hash('sha256', webauthn_normalize_username($username)), 0, 16);
	return webauthn_with_lock(WEBAUTHN_USED_FILE, function () use ($challenge, $nonce, $expires, $now, $verify, $who) {
		$used = webauthn_used_nonces($now);
		if ($used === null || isset($used[$nonce]) || count($used) >= WEBAUTHN_MAX_LIVE_NONCES) {
			return null;
		}
		/* Per user too: one account completing ceremonies over and over
		 * only blocks itself, never everyone else's sign-ins. */
		$mine = count(array_filter($used, function ($v) use ($who) {
			return is_array($v) && ($v['u'] ?? null) === $who;
		}));
		if ($mine >= WEBAUTHN_MAX_LIVE_NONCES_PER_USER) {
			return null;
		}
		$result = $verify($challenge);
		$used[$nonce] = ['e' => $expires, 'u' => $who];
		if (!webauthn_write_json(WEBAUTHN_USED_FILE, $used)) {
			throw new WebAuthnException('The used-challenge list could not be written');
		}
		return $result;
	}, null);
}

/**
 * Unexpired used nonces (nonce => expiry); null when the list cannot be
 * trusted: a damaged list may hold nonces that are still valid, so it is
 * refused until every challenge it could hold has expired. Call with the
 * used-challenge lock held.
 * @return array<string, mixed>|null
 */
function webauthn_used_nonces(int $now): ?array {
	$raw = @file_get_contents(WEBAUTHN_USED_FILE);
	$used = ($raw === false) ? (file_exists(WEBAUTHN_USED_FILE) ? null : []) : json_decode($raw, true);
	if (!is_array($used)) {
		clearstatcache(true, WEBAUTHN_USED_FILE);
		if ($now - (int)@filemtime(WEBAUTHN_USED_FILE) <= WEBAUTHN_CHALLENGE_TTL) {
			return null;
		}
		$used = [];
	}
	/* Entries are ['e' => expiry, 'u' => user hash]; older ones a bare expiry. */
	return array_filter($used, function ($v) use ($now) {
		$exp = is_int($v) ? $v : (is_array($v) && is_int($v['e'] ?? null) ? $v['e'] : 0);
		return $exp >= $now;
	});
}
