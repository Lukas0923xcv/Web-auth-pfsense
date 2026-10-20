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
	/* Kept on disk: losing the list (e.g. at reboot) would make used challenges valid again. */
	define('WEBAUTHN_USED_FILE', '/conf/webauthn_used_challenges.json');
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
		/* Source addresses allowed to use XMLRPC (HA sync) while enabled. */
		'xmlrpc_peers' => '',
	];
}

function webauthn_settings(): array {
	$s = config_get_path(WEBAUTHN_CONFIG_PATH, []);
	return array_merge(webauthn_default_settings(), is_array($s) ? $s : []);
}

/*
 * Passkeys belong to the exact username (surrounding spaces trimmed).
 * pfSense local accounts are case-sensitive, so "Bob" and "bob" can be
 * two different people: they must never share passkeys.
 */
function webauthn_normalize_username(?string $username): string {
	return trim((string)$username);
}

/*
 * A username the way directories compare names (RFC 4518): compatibility
 * forms (NFKC), no soft hyphens, zero-width or other ignorable characters,
 * runs of spaces collapsed, case folded.
 */
function webauthn_username_fold(?string $username): string {
	$u = (string)$username;
	if (class_exists('Normalizer')) {
		$n = Normalizer::normalize($u, Normalizer::FORM_KC);
		$u = ($n === false) ? $u : $n;
	}
	$u = preg_replace('/[\p{Cf}\p{Cc}\x{034F}\x{1806}\x{180B}-\x{180D}\x{FE00}-\x{FE0F}\x{FFFC}]/u', '', $u) ?? $u;
	$u = trim(preg_replace('/[\p{Z}\s]+/u', ' ', $u) ?? $u);
	return function_exists('mb_convert_case') ? mb_convert_case($u, MB_CASE_FOLD, 'UTF-8') : strtolower($u);
}

/*
 * The account names an authentication backend may take $username to
 * mean, used only to stop other spellings of a remote (LDAP/RADIUS)
 * account from skipping the passkey step. pfSense's LDAP code keeps the
 * part before "@" and before "\"; RADIUS servers usually strip a realm
 * ("user@realm", "REALM\user", "realm/user"). So "admin@x", "admin\x",
 * "CORP\admin" and "ADMIN" can all sign in as "admin".
 *
 * $login: the name typed at sign-in. Only for it is the part before "\"
 * a candidate (pfSense's LDAP quirk); for a stored passkey owner it is
 * just a domain, and two users of one domain must not match each other.
 */
function webauthn_username_keys(?string $username, bool $login): array {
	$u = webauthn_username_fold($username);
	$parts = [$u];
	if (str_contains($u, '\\')) {
		[$before, $after] = explode('\\', $u, 2);
		$parts[] = $after;
		if ($login) {
			$parts[] = $before;
		}
	}
	if (str_contains($u, '/')) {
		$parts[] = substr($u, strrpos($u, '/') + 1);
	}
	$keys = [];
	foreach ($parts as $p) {
		$keys[] = trim($p);
		$keys[] = trim(explode('@', $p, 2)[0]);
	}
	return array_values(array_unique(array_filter($keys, 'strlen')));
}

/*
 * Did this session sign in against pfSense's own user database? Local
 * names are exact and case-sensitive: "Bob" and "bob" are two accounts.
 */
function webauthn_session_is_local(array $session): bool {
	return in_array($session['authsource'] ?? null, ['Local Database', 'Local Database Fallback'], true);
}

/* Passkeys registered under another spelling of the sign-in name $username (see webauthn_username_keys()). */
function webauthn_case_variant_credentials(string $username): array {
	$out = [];
	$mine = webauthn_username_keys($username, true);
	foreach (webauthn_all_credentials() as $c) {
		$name = webauthn_normalize_username($c['username'] ?? '');
		if ($name !== webauthn_normalize_username($username) &&
		    !empty(array_intersect(webauthn_username_keys($name, false), $mine))) {
			$out[] = $c;
		}
	}
	return $out;
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

/*
 * Where a GUI session stands with respect to the second factor.
 *   'disabled'  - the second factor is off
 *   'verified'  - passed WebAuthn with a passkey that is still registered
 *   'skip'      - exempt for this request (trusted network, or no passkey
 *                 while enforcement is off)
 *   'require'   - must pass WebAuthn now
 *   'deny'      - no passkey and enforcement is on
 * $session is $_SESSION. Removing a passkey revokes the sessions it
 * verified, because 'verified' re-checks that the passkey still exists.
 */
function webauthn_session_status(array $settings, array $session, array $source): string {
	if (empty($settings['enable'])) {
		return 'disabled';
	}
	$user = webauthn_normalize_username($session['Username'] ?? '');
	if ($user === '') {
		return 'require';
	}
	$state = $session['webauthn'] ?? null;
	if (is_array($state) && ($state['method'] ?? null) === 'webauthn' &&
	    webauthn_normalize_username($state['user'] ?? '') === $user) {
		if (is_string($state['credential'] ?? null) && webauthn_find_credential($user, $state['credential']) !== null) {
			return 'verified';
		}
		/* Its passkey was removed: the session ends, even if the user has
		 * no passkey left and would otherwise skip the step. */
		return 'revoked';
	}
	return webauthn_gate_decision($settings, $source, webauthn_session_has_credentials($session));
}

/*
 * Does the session's user have passkeys? For remote accounts, another
 * spelling with passkeys counts too: it must not skip the step.
 */
function webauthn_session_has_credentials(array $session): bool {
	$user = webauthn_normalize_username($session['Username'] ?? '');
	return !empty(webauthn_get_credentials($user)) ||
	    (!webauthn_session_is_local($session) && !empty(webauthn_case_variant_credentials($user)));
}

/*
 * May this session register a passkey? Once the account (or, for remote
 * accounts, another spelling of it) has a passkey, only a session that
 * signed in with one may add another. Otherwise a password alone, from a
 * trusted network or while enforcement is off, would be enough to enrol
 * an attacker's passkey for later use through the tunnel.
 */
function webauthn_may_register(array $settings, array $session, array $source): bool {
	return !webauthn_session_has_credentials($session) ||
	    in_array(webauthn_session_status($settings, $session, $source), ['disabled', 'verified'], true);
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
	foreach (['trusted_proxies' => gettext('cloudflared source'), 'trusted_networks' => gettext('Trusted network'),
	    'xmlrpc_peers' => gettext('XMLRPC peer')] as $field => $label) {
		foreach (webauthn_split_list($s[$field] ?? '') as $c) {
			if (!webauthn_valid_cidr($c)) {
				$errors[] = sprintf(gettext('%1$s entry %2$s is not a valid IP address or CIDR.'), $label, htmlspecialchars($c));
			}
		}
	}
	/* A cloudflared address inside a trusted network is fine (tunnel
	 * traffic is never exempt), but a /0 entry (however written, e.g. /00)
	 * would exempt everyone. */
	$trusted = webauthn_split_list($s['trusted_networks'] ?? '');
	foreach ($trusted as $c) {
		$parts = explode('/', $c, 2);
		if (isset($parts[1]) && ctype_digit($parts[1]) && (int)$parts[1] === 0) {
			$errors[] = gettext('A /0 trusted network would disable WebAuthn for everyone.');
		}
	}
	foreach (webauthn_split_list($s['xmlrpc_peers'] ?? '') as $c) {
		$parts = explode('/', $c, 2);
		if (isset($parts[1]) && ctype_digit($parts[1]) && (int)$parts[1] === 0) {
			$errors[] = gettext('A /0 XMLRPC peer would let every host use XMLRPC with a password alone.');
		}
	}
	/* Without the cloudflared address, tunnel traffic from a LAN host is
	 * only told apart from LAN traffic by its proxy headers. */
	if (!empty($trusted) && empty(webauthn_split_list($s['trusted_proxies'] ?? ''))) {
		$errors[] = gettext('Set the cloudflared source before adding trusted networks, so tunnel traffic can never be mistaken for local traffic.');
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

/*
 * Raise a GUI notice (the bell icon; also sent through any configured
 * notification channels such as e-mail) for security-relevant events.
 */
function webauthn_notice(string $message): void {
	if (!function_exists('file_notice')) {
		@include_once('notices.inc');
	}
	if (function_exists('file_notice')) {
		file_notice('webauthn', $message, 'WebAuthn');
	}
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
		if ($username === null || webauthn_normalize_username($c['username'] ?? '') === webauthn_normalize_username($username)) {
			$out[] = $c;
		}
	}
	return $out;
}

function webauthn_add_credential(string $username, string $name, array $reg, string $rp_id): void {
	$all = webauthn_all_credentials();
	$all[] = [
		'username' => webauthn_normalize_username($username),
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
		if (($c['id'] ?? null) === $id && ($username === null ||
		    webauthn_normalize_username($c['username'] ?? '') === webauthn_normalize_username($username))) {
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
	webauthn_with_lock(WEBAUTHN_COUNTER_FILE, function () use ($id, $count) {
		$data = json_decode((string)@file_get_contents(WEBAUTHN_COUNTER_FILE), true);
		$data = is_array($data) ? $data : [];
		$data[$id] = $count;
		return webauthn_write_json(WEBAUTHN_COUNTER_FILE, $data);
	});
}

/* Run $fn holding an exclusive lock on "$file.lock"; $fail if the lock cannot be taken. */
function webauthn_with_lock(string $file, callable $fn, $fail = false) {
	$old = umask(077);
	$lock = @fopen($file . '.lock', 'c');
	umask($old);
	if ($lock === false) {
		return $fail;
	}
	if (!flock($lock, LOCK_EX)) {
		fclose($lock);
		return $fail;
	}
	try {
		return $fn();
	} finally {
		flock($lock, LOCK_UN);
		fclose($lock);
	}
}

/*
 * Replace $file with $data as JSON through a temp file and rename, so a
 * failed write (e.g. a full disk) never leaves a truncated file behind.
 */
function webauthn_write_json(string $file, array $data): bool {
	$json = json_encode($data);
	$tmp = $file . '.tmp';
	$old = umask(077);
	$ok = @file_put_contents($tmp, $json) === strlen($json) && @rename($tmp, $file);
	umask($old);
	if (!$ok) {
		@unlink($tmp);
	}
	return $ok;
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
	$sid = session_id();
	if ($sid === '' || $sid === false) {
		$sid = (string)($_COOKIE[session_name()] ?? '');
	}
	$data = implode("\0", [$purpose, $sid, webauthn_normalize_username($username), $payload]);
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

/*
 * Record a nonce as used. False if it was already used, or if that
 * cannot be known (the list cannot be read or written).
 */
function webauthn_mark_nonce_used(string $nonce, int $expires): bool {
	return webauthn_with_lock(WEBAUTHN_USED_FILE, function () use ($nonce, $expires) {
		$now = time();
		$raw = @file_get_contents(WEBAUTHN_USED_FILE);
		$used = ($raw === false) ? [] : json_decode($raw, true);
		if (!is_array($used)) {
			/* A damaged list may hold nonces that are still valid: refuse
			 * until every challenge it could hold has expired. */
			clearstatcache(true, WEBAUTHN_USED_FILE);
			if ($now - (int)@filemtime(WEBAUTHN_USED_FILE) <= WEBAUTHN_CHALLENGE_TTL) {
				return false;
			}
			$used = [];
		}
		$used = array_filter($used, function ($exp) use ($now) {
			return $exp >= $now;
		});
		$fresh = !isset($used[$nonce]);
		$used[$nonce] = $expires;
		return webauthn_write_json(WEBAUTHN_USED_FILE, $used) && $fresh;
	});
}
