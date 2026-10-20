<?php
/*
 * webauthn.inc
 *
 * pfSense glue for the WebAuthn second factor: settings, credential
 * storage, access-path policy (Cloudflare Tunnel / trusted networks),
 * client IP resolution, and logging.
 *
 * Licensed under the Apache License, Version 2.0.
 */

require_once(__DIR__ . '/webauthn_lib.inc');

define('WEBAUTHN_CONFIG_PATH', 'installedpackages/webauthn/config/0');
/*
 * Lists in config.xml must use a tag from pfSense's listtags() set
 * (xmlparse.inc); any other tag holding a list is written as <0>, <1>,
 * ... which is invalid XML and makes pfSense restore a backup.
 */
define('WEBAUTHN_CRED_PATH', 'installedpackages/webauthn/item');
if (!defined('WEBAUTHN_COUNTER_FILE')) {
	define('WEBAUTHN_COUNTER_FILE', '/conf/webauthn_signcount.json');
}
if (!defined('WEBAUTHN_KEY_FILE')) {
	define('WEBAUTHN_KEY_FILE', '/conf/webauthn_challenge.key');
}
if (!defined('WEBAUTHN_USED_FILE')) {
	define('WEBAUTHN_USED_FILE', '/tmp/webauthn_used_challenges.json');
}
define('WEBAUTHN_MAX_FAILURES', 5);
define('WEBAUTHN_CHALLENGE_TTL', 300);

function webauthn_default_settings(): array {
	return [
		'enable' => '',
		/* RP ID: the public hostname, or a parent domain of it. */
		'rp_id' => '',
		/* Origins allowed in clientDataJSON, one per line. */
		'origins' => '',
		/* Source addresses of cloudflared (IPs or CIDRs). */
		'trusted_proxies' => '',
		/* Source networks that skip the WebAuthn step. */
		'trusted_networks' => '',
		/* discouraged | preferred | required */
		'user_verification' => 'preferred',
		/* Users without a passkey are refused unless on a trusted network. */
		'enforce' => '',
	];
}

function webauthn_settings(): array {
	$s = config_get_path(WEBAUTHN_CONFIG_PATH, []);
	return array_merge(webauthn_default_settings(), is_array($s) ? $s : []);
}

/* Split a whitespace/comma separated list, dropping empties. */
function webauthn_split_list(?string $s): array {
	return array_values(array_filter(preg_split('/[\s,]+/', (string)$s), 'strlen'));
}

/* Does $ip fall within $cidr (an address or address/prefix, v4 or v6)? */
function webauthn_ip_in_cidr(string $ip, string $cidr): bool {
	$parts = explode('/', $cidr, 2);
	$net = @inet_pton($parts[0]);
	$addr = @inet_pton($ip);
	if ($net === false || $addr === false || strlen($net) != strlen($addr)) {
		return false;
	}
	$bits = strlen($addr) * 8;
	if (isset($parts[1])) {
		if (!ctype_digit($parts[1]) || (int)$parts[1] > $bits) {
			return false;
		}
		$prefix = (int)$parts[1];
	} else {
		$prefix = $bits;
	}
	$full = intdiv($prefix, 8);
	if (substr($addr, 0, $full) !== substr($net, 0, $full)) {
		return false;
	}
	$rem = $prefix % 8;
	if ($rem == 0) {
		return true;
	}
	$mask = (0xff << (8 - $rem)) & 0xff;
	return (ord($addr[$full]) & $mask) == (ord($net[$full]) & $mask);
}

function webauthn_ip_in_list(string $ip, array $list): bool {
	foreach ($list as $cidr) {
		if (webauthn_ip_in_cidr($ip, $cidr)) {
			return true;
		}
	}
	return false;
}

function webauthn_valid_cidr(string $cidr): bool {
	$parts = explode('/', $cidr, 2);
	$bin = @inet_pton($parts[0]);
	if ($bin === false) {
		return false;
	}
	return !isset($parts[1]) || (ctype_digit($parts[1]) && (int)$parts[1] <= strlen($bin) * 8);
}

/*
 * Describe where a request came from.
 *
 * $server is $_SERVER. CF-Connecting-IP is only believed when the TCP
 * peer is one of the configured cloudflared addresses; from anyone else
 * it could be forged.
 *
 * Returns:
 *   peer        - the TCP peer pfSense sees (REMOTE_ADDR)
 *   client      - the best-known real client address
 *   via_proxy   - the peer is a configured cloudflared address
 *   proxy_headers - the request carries Cloudflare or other reverse-proxy
 *                   headers, i.e. it was forwarded on someone's behalf
 */
function webauthn_request_source(array $server, array $settings): array {
	$peer = (string)($server['REMOTE_ADDR'] ?? '');
	$via_proxy = ($peer !== '') && webauthn_ip_in_list($peer, webauthn_split_list($settings['trusted_proxies']));
	$cf_ip = trim((string)($server['HTTP_CF_CONNECTING_IP'] ?? ''));
	$client = $peer;
	if ($via_proxy && $cf_ip !== '' && filter_var($cf_ip, FILTER_VALIDATE_IP) !== false) {
		$client = $cf_ip;
	}
	return [
		'peer' => $peer,
		'client' => $client,
		'via_proxy' => $via_proxy,
		'proxy_headers' => isset($server['HTTP_CF_CONNECTING_IP']) || isset($server['HTTP_CF_RAY']) ||
		    isset($server['HTTP_CF_ACCESS_JWT_ASSERTION']) || isset($server['HTTP_X_FORWARDED_FOR']) ||
		    isset($server['HTTP_FORWARDED']) || isset($server['HTTP_X_REAL_IP']),
	];
}

/*
 * May this request skip the WebAuthn step because it comes from a
 * trusted local network?
 *
 * Anything arriving through the tunnel never qualifies, even if
 * cloudflared itself sits inside a trusted network (for example on the
 * LAN or on pfSense at 127.0.0.1): otherwise every Internet user would
 * inherit the LAN's exemption. Forwarded requests are recognised by the
 * configured cloudflared address and, as a fallback when that is not
 * configured, by proxy headers such as X-Forwarded-For.
 */
function webauthn_source_is_trusted_network(array $source, array $settings): bool {
	if ($source['via_proxy'] || $source['proxy_headers'] || $source['peer'] === '') {
		return false;
	}
	return webauthn_ip_in_list($source['peer'], webauthn_split_list($settings['trusted_networks']));
}

/*
 * Decide what the gate does for a password-authenticated session that
 * has not yet passed WebAuthn.
 *   'skip'     - let the request through without WebAuthn
 *   'require'  - show the WebAuthn challenge
 *   'deny'     - user has no passkey and enforcement is on
 */
function webauthn_gate_decision(array $settings, array $source, bool $has_credentials): string {
	if (empty($settings['enable'])) {
		return 'skip';
	}
	if (webauthn_source_is_trusted_network($source, $settings)) {
		return 'skip';
	}
	if ($has_credentials) {
		return 'require';
	}
	return empty($settings['enforce']) ? 'skip' : 'deny';
}

function webauthn_rp_id(?array $settings = null): string {
	$settings = $settings ?? webauthn_settings();
	return strtolower(trim($settings['rp_id']));
}

/* Origins accepted in clientDataJSON. Defaults to https://<rp_id>. */
function webauthn_allowed_origins(?array $settings = null): array {
	$settings = $settings ?? webauthn_settings();
	$origins = array_map('webauthn_normalize_origin', webauthn_split_list($settings['origins']));
	if (empty($origins) && webauthn_rp_id($settings) !== '') {
		$origins = ['https://' . webauthn_rp_id($settings)];
	}
	return $origins;
}

function webauthn_require_uv(?array $settings = null): bool {
	$settings = $settings ?? webauthn_settings();
	return $settings['user_verification'] === 'required';
}

/* Validate settings submitted from the GUI. Returns a list of errors. */
function webauthn_validate_settings(array $s): array {
	$errors = [];
	$rp_id = strtolower(trim($s['rp_id'] ?? ''));
	if (!empty($s['enable']) && $rp_id === '') {
		$errors[] = gettext('An RP ID is required when WebAuthn is enabled.');
	}
	if ($rp_id !== '') {
		if (filter_var($rp_id, FILTER_VALIDATE_IP) !== false) {
			$errors[] = gettext('The RP ID must be a domain name; passkeys cannot be bound to an IP address.');
		} elseif (!preg_match('/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/', $rp_id)) {
			$errors[] = gettext('The RP ID must be a fully qualified domain name (for example pfsense.example.com or example.com).');
		}
	}
	$origins = webauthn_split_list($s['origins'] ?? '');
	foreach ($origins as $o) {
		if (!webauthn_origin_matches_rp(webauthn_normalize_origin($o), $rp_id)) {
			$errors[] = sprintf(gettext('Origin %1$s must be https:// and its host must be %2$s or a subdomain of it.'),
			    htmlspecialchars($o), htmlspecialchars($rp_id));
		}
	}
	foreach (['trusted_proxies' => gettext('cloudflared source'), 'trusted_networks' => gettext('Trusted network')] as $field => $label) {
		foreach (webauthn_split_list($s[$field] ?? '') as $c) {
			if (!webauthn_valid_cidr($c)) {
				$errors[] = sprintf(gettext('%1$s entry %2$s is not a valid IP address or CIDR.'), $label, htmlspecialchars($c));
			}
		}
	}
	/* A cloudflared address inside a trusted network is fine (tunnel
	 * traffic is never exempt), but a 0.0.0.0/0-style entry is a mistake. */
	foreach (webauthn_split_list($s['trusted_networks'] ?? '') as $c) {
		if (preg_match('#/0$#', $c)) {
			$errors[] = gettext('A /0 trusted network would disable WebAuthn for everyone.');
		}
	}
	if (!in_array($s['user_verification'] ?? '', ['discouraged', 'preferred', 'required'], true)) {
		$errors[] = gettext('Invalid user verification setting.');
	}
	return $errors;
}

/*
 * Log to syslog with the USER facility and a message format that does
 * not match sshguard's "webConfigurator authentication error" pattern,
 * so WebAuthn failures never add the cloudflared address (shared by all
 * tunnel users) to the GUI lockout table.
 */
function webauthn_log(int $level, string $message, ?array $source = null): void {
	if ($source !== null) {
		$message .= ' from ' . $source['client'];
		if ($source['via_proxy']) {
			$message .= ' (via cloudflared ' . $source['peer'] . ')';
		}
	}
	$message = preg_replace('/[\x00-\x1f\x7f]/', ' ', $message);
	syslog(LOG_USER | $level, 'webauthn: ' . $message);
}

/* ---- Credential storage ---- */

/*
 * All stored credentials as a list. <item> is a pfSense list tag, so it
 * always parses as a list; wrap a bare element anyway in case one was
 * written by hand.
 */
function webauthn_all_credentials(): array {
	$all = config_get_path(WEBAUTHN_CRED_PATH, []);
	if (!is_array($all)) {
		return [];
	}
	if (isset($all['id']) && !is_array($all['id'])) {
		$all = [$all];
	}
	return array_values(array_filter($all, 'is_array'));
}

function webauthn_get_credentials(?string $username = null): array {
	$out = [];
	foreach (webauthn_all_credentials() as $c) {
		if (($username === null || ($c['username'] ?? null) === $username)) {
			$out[] = $c;
		}
	}
	return $out;
}

function webauthn_add_credential(string $username, string $name, array $reg, string $rp_id): void {
	$all = webauthn_all_credentials();
	$all[] = [
		'username' => $username,
		'name' => $name,
		'id' => webauthn_b64url_encode($reg['credential_id']),
		'alg' => (string)$reg['alg'],
		'publickey' => base64_encode($reg['pem']),
		'rp_id' => $rp_id,
		'created' => (string)time(),
	];
	config_set_path(WEBAUTHN_CRED_PATH, $all);
	write_config(sprintf('WebAuthn: registered passkey "%s" for user %s', $name, $username));
	webauthn_set_sign_count($all[count($all) - 1]['id'], (int)$reg['sign_count']);
}

/* Delete a credential; restrict to $username unless null (admin). */
function webauthn_delete_credential(string $id, ?string $username = null): bool {
	$all = webauthn_all_credentials();
	foreach ($all as $i => $c) {
		if (($c['id'] ?? null) === $id && ($username === null || ($c['username'] ?? null) === $username)) {
			unset($all[$i]);
			config_set_path(WEBAUTHN_CRED_PATH, array_values($all));
			write_config(sprintf('WebAuthn: removed passkey "%s" of user %s', $c['name'] ?? '', $c['username'] ?? ''));
			return true;
		}
	}
	return false;
}

/*
 * Signature counters are kept outside config.xml so that every login
 * does not create a configuration revision.
 */
function webauthn_get_sign_count(string $id): int {
	$data = @json_decode((string)@file_get_contents(WEBAUTHN_COUNTER_FILE), true);
	return (int)($data[$id] ?? 0);
}

function webauthn_set_sign_count(string $id, int $count): void {
	$fp = @fopen(WEBAUTHN_COUNTER_FILE, 'c+');
	if ($fp === false) {
		return;
	}
	flock($fp, LOCK_EX);
	$data = json_decode(stream_get_contents($fp), true);
	$data = is_array($data) ? $data : [];
	$data[$id] = $count;
	ftruncate($fp, 0);
	rewind($fp);
	fwrite($fp, json_encode($data));
	flock($fp, LOCK_UN);
	fclose($fp);
	@chmod(WEBAUTHN_COUNTER_FILE, 0600);
}

/* Find a stored credential for $username by its base64url ID. */
function webauthn_find_credential(string $username, string $id): ?array {
	foreach (webauthn_get_credentials($username) as $c) {
		if (hash_equals((string)$c['id'], $id)) {
			$c['pem'] = base64_decode($c['publickey']);
			$c['sign_count'] = webauthn_get_sign_count($c['id']);
			return $c;
		}
	}
	return null;
}

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
	if ($key === false || strlen($key) != 32) {
		$key = random_bytes(32);
		$old = umask(077);
		file_put_contents(WEBAUTHN_KEY_FILE, $key, LOCK_EX);
		umask($old);
	}
	return $key;
}

function webauthn_challenge_mac(string $purpose, string $username, string $payload): string {
	$sid = session_id();
	if ($sid === '' || $sid === false) {
		$sid = (string)($_COOKIE[session_name()] ?? '');
	}
	$data = implode("\0", [$purpose, $sid, $username, $payload]);
	return substr(hash_hmac('sha256', $data, webauthn_hmac_key(), true), 0, 16);
}

function webauthn_new_challenge(string $purpose, string $username): string {
	$payload = random_bytes(16) . pack('N', time() + WEBAUTHN_CHALLENGE_TTL);
	return $payload . webauthn_challenge_mac($purpose, $username, $payload);
}

/*
 * Validate the challenge the browser signed (taken from clientDataJSON)
 * and mark it used. Returns the raw challenge, or null if it is forged,
 * expired, for another session/user/purpose, or already used. The
 * ceremony verification then checks clientDataJSON against it again.
 */
function webauthn_take_challenge(string $purpose, string $username, string $client_data_json): ?string {
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
	if ($expires < time()) {
		return null;
	}
	return webauthn_mark_nonce_used(bin2hex(substr($payload, 0, 16)), $expires) ? $challenge : null;
}

/* Record a nonce as used; false if it was already used. */
function webauthn_mark_nonce_used(string $nonce, int $expires): bool {
	$fp = @fopen(WEBAUTHN_USED_FILE, 'c+');
	if ($fp === false) {
		return false;
	}
	flock($fp, LOCK_EX);
	$used = json_decode(stream_get_contents($fp), true);
	$used = is_array($used) ? $used : [];
	$now = time();
	$used = array_filter($used, function ($exp) use ($now) {
		return $exp >= $now;
	});
	$fresh = !isset($used[$nonce]);
	$used[$nonce] = $expires;
	ftruncate($fp, 0);
	rewind($fp);
	fwrite($fp, json_encode($used));
	flock($fp, LOCK_UN);
	fclose($fp);
	return $fresh;
}
