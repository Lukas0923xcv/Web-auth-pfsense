<?php
/*
 * webauthn.inc
 *
 * pfSense glue for the WebAuthn second factor: settings, usernames,
 * access-path policy (Cloudflare Tunnel / trusted networks), client IP
 * resolution, logging and notices. Passkey storage is in storage.inc,
 * challenges in challenge.inc.
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
if (!defined('WEBAUTHN_REVOKED_FILE')) {
	/* IDs of removed passkeys: never accepted again, even if a config
	 * restore or a stale write brings the record back. */
	define('WEBAUTHN_REVOKED_FILE', '/conf/webauthn_revoked.json');
}
if (!defined('WEBAUTHN_CONFIG_LOCK')) {
	/* Serialises changes to installedpackages/webauthn (".lock" is appended). */
	define('WEBAUTHN_CONFIG_LOCK', '/conf/webauthn_config');
}
if (!defined('WEBAUTHN_NOTICE_FILE')) {
	define('WEBAUTHN_NOTICE_FILE', '/conf/webauthn_notices.json');
}
if (!defined('WEBAUTHN_RUN_DIR')) {
	/* Fallback markers when /conf cannot be written (cleared at reboot). */
	define('WEBAUTHN_RUN_DIR', '/var/run');
}
if (!defined('WEBAUTHN_STATE_FILE')) {
	/* Hash of installedpackages/webauthn as last saved by this package. */
	define('WEBAUTHN_STATE_FILE', '/conf/webauthn_state.json');
}
if (!defined('WEBAUTHN_FAILURE_FILE')) {
	/* Failed passkey attempts per account (see webauthn_failure_begin()). */
	define('WEBAUTHN_FAILURE_FILE', '/conf/webauthn_failures.json');
}
/* Failed passkey attempts in one session before it is ended. */
define('WEBAUTHN_MAX_FAILURES', 5);
/* Passkey attempts per account and client address, over all sessions,
 * before that address is locked out of the account's passkey step for
 * WEBAUTHN_FAILURE_WINDOW seconds. */
define('WEBAUTHN_MAX_USER_FAILURES', 10);
define('WEBAUTHN_FAILURE_WINDOW', 900);
define('WEBAUTHN_CHALLENGE_TTL', 300);
/* A passkey verification is good for this long at most (seconds). */
define('WEBAUTHN_VERIFIED_MAX_AGE', 12 * 3600);
/* Upper bound for unexpired entries in the used-challenge list, in all and per user. */
define('WEBAUTHN_MAX_LIVE_NONCES', 10000);
define('WEBAUTHN_MAX_LIVE_NONCES_PER_USER', 50);
/* Passkeys per account. */
define('WEBAUTHN_MAX_CREDENTIALS_PER_USER', 20);
/* At most one failed-attempt notice per user in this many seconds. */
define('WEBAUTHN_NOTICE_INTERVAL', 900);

require_once(__DIR__ . '/storage.inc');
require_once(__DIR__ . '/challenge.inc');

/**
 * @return WebAuthnSettings
 */
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

/* The installed version of this package (the VERSION file next to this one). */
function webauthn_version(): string {
	$v = trim((string)@file_get_contents(__DIR__ . '/VERSION'));
	return preg_match('/^[0-9A-Za-z.\-]{1,32}$/', $v) ? $v : 'unknown';
}

/**
 * @return WebAuthnSettings
 */
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
 * Can usernames be compared the way directories do? That needs PHP's intl
 * (Normalizer) and mbstring extensions. $set overrides the answer (tests).
 */
function webauthn_unicode_available(?bool $set = null): bool {
	static $override = null;
	if ($set !== null) {
		$override = $set;
	}
	return $override ?? (class_exists('Normalizer') && function_exists('mb_convert_case') && function_exists('mb_convert_kana'));
}

/*
 * A username the way directories compare names (RFC 4518): compatibility
 * forms (NFKC), no soft hyphens, zero-width or other ignorable characters,
 * runs of spaces collapsed, case folded, katakana as hiragana (Active
 * Directory ignores the kana type). Without intl/mbstring only ASCII is
 * folded; webauthn_session_has_credentials() then fails closed.
 */
function webauthn_username_fold(?string $username): string {
	$u = (string)$username;
	$unicode = webauthn_unicode_available();
	if ($unicode) {
		$n = Normalizer::normalize($u, Normalizer::FORM_KC);
		$u = ($n === false) ? $u : $n;
	}
	$u = preg_replace('/[\p{Cf}\p{Cc}\x{034F}\x{1806}\x{180B}-\x{180D}\x{FE00}-\x{FE0F}\x{FFFC}]/u', '', $u) ?? $u;
	$u = trim(preg_replace('/[\p{Z}\s]+/u', ' ', $u) ?? $u);
	if (!$unicode) {
		return strtolower($u);
	}
	return mb_convert_kana(mb_convert_case($u, MB_CASE_FOLD, 'UTF-8'), 'c', 'UTF-8');
}

/**
 * The account names an authentication backend may take $username to
 * mean, used only to stop other spellings of a remote (LDAP/RADIUS)
 * account from skipping the passkey step. pfSense's LDAP code keeps the
 * part before "@" and before "\"; RADIUS servers usually strip a realm
 * ("user@realm", "user%realm", "REALM\user", "realm/user"). So "admin@x", "admin\x",
 * "CORP\admin" and "ADMIN" can all sign in as "admin".
 *
 * $login: the name typed at sign-in. Only for it is the part before "\"
 * a candidate (pfSense's LDAP quirk); for a stored passkey owner it is
 * just a domain, and two users of one domain must not match each other.
 * @return list<string>
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
		/* "user@realm" and "user%realm" */
		$keys[] = trim(preg_split('/[@%]/', $p, 2)[0]);
	}
	return array_values(array_unique(array_filter($keys, fn(string $k) => $k !== '')));
}

/**
 * Did this session sign in against pfSense's own user database? Local
 * names are exact and case-sensitive: "Bob" and "bob" are two accounts.
 * @param WebAuthnSession $session
 */
function webauthn_session_is_local(array $session): bool {
	return in_array($session['authsource'] ?? null, ['Local Database', 'Local Database Fallback'], true);
}

/**
 * The local account named $name, or null. pfSense's getUserEntry() looks
 * names up through an array index; PHP turns only canonical decimal
 * strings into integer keys, so that lookup is an exact string match,
 * which this repeats without depending on auth.inc being loaded. With
 * duplicate names the last entry wins, as in pfSense's index.
 * @return array<string, mixed>|null
 */
function webauthn_local_user(string $name): ?array {
	$found = null;
	$users = config_get_path('system/user', []);
	$users = is_array($users) ? (isset($users['name']) && !is_array($users['name']) ? [$users] : $users) : [];
	foreach ($users as $u) {
		if (is_array($u) && isset($u['name']) && (string)$u['name'] === $name) {
			$found = $u;
		}
	}
	return $found;
}

/**
 * The account a session belongs to, as passkey owner. For local accounts
 * it is the name the user database resolves the sign-in name to, and ''
 * when it resolves to none: such a session has to pass the passkey step
 * and cannot (fail closed). Remote accounts keep the sign-in name.
 * @param WebAuthnSession $session
 */
function webauthn_session_identity(array $session): string {
	$typed = webauthn_normalize_username($session['Username'] ?? '');
	if ($typed === '' || !webauthn_session_is_local($session)) {
		return $typed;
	}
	$entry = webauthn_local_user($typed);
	return is_array($entry) ? webauthn_normalize_username((string)$entry['name']) : '';
}

/* The PHP session ID a verification is bound to. */
function webauthn_session_sid(): string {
	$sid = session_id();
	if ($sid === '' || $sid === false) {
		$sid = (string)($_COOKIE[session_name()] ?? '');
	}
	return (string)$sid;
}

/*
 * Is this request a password sign-in (pfSense's login form)? The same test
 * as session_auth(): "login" set and a username given. A POST with an
 * empty username is no sign-in for pfSense, so it must not end the
 * passkey verification either (review finding F4: a cross-site POST could
 * otherwise strip it).
 */
function webauthn_is_login_post(): bool {
	return isset($_POST['login']) && is_string($_POST['usernamefld'] ?? null) && $_POST['usernamefld'] !== '';
}

/**
 * May passkeys be stored under this session's name? Not if it holds
 * control or format characters (they would end up in config.xml). For
 * LDAP and RADIUS, not if it contains "\" or "/": the part after them
 * would make the passkey count for another account, although the backend
 * may have authenticated the part before (pfSense signs "x\carol" in as
 * LDAP user x). Such users register under their plain name.
 * @param WebAuthnSession $session
 */
function webauthn_registrable_name(array $session): bool {
	$u = webauthn_session_identity($session);
	if ($u === '' || preg_match('//u', $u) !== 1 || preg_match('/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u', $u)) {
		return false;
	}
	return webauthn_session_is_local($session) || (!str_contains($u, '\\') && !str_contains($u, '/'));
}

/**
 * Passkeys registered under another spelling of the sign-in name $username (see webauthn_username_keys()).
 * @return list<WebAuthnCredential>
 */
function webauthn_case_variant_credentials(string $username): array {
	$out = [];
	$mine = webauthn_username_keys($username, true);
	foreach (webauthn_all_credentials() as $c) {
		$name = webauthn_normalize_username($c['username'] ?? '');
		if ($name !== webauthn_normalize_username($username) &&
		    !empty(array_intersect(webauthn_credential_keys($c), $mine))) {
			$out[] = $c;
		}
	}
	return $out;
}

/**
 * The names a stored passkey stands for: every spelling a backend may
 * take for its owner (see webauthn_username_keys()). Deliberately broad:
 * a passkey that stands for too many names can only refuse someone, one
 * that stands for too few lets another spelling skip the passkey step.
 * @param WebAuthnCredential $c
 * @return list<string>
 */
function webauthn_credential_keys(array $c): array {
	return webauthn_username_keys(webauthn_normalize_username($c['username'] ?? ''), false);
}

/**
 * Split a whitespace/comma separated list, dropping empties.
 * @return list<string>
 */
function webauthn_split_list(?string $s): array {
	return array_values(array_filter(preg_split('/[\s,]+/', (string)$s), fn(string $x) => $x !== ''));
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

/**
 * @param array<string> $list
 */
function webauthn_ip_in_list(string $ip, array $list): bool {
	foreach ($list as $cidr) {
		if (webauthn_ip_in_cidr($ip, $cidr)) {
			return true;
		}
	}
	return false;
}

/* Is the prefix shorter than /8 (IPv4) or /16 (IPv6)? */
function webauthn_cidr_too_large(string $cidr): bool {
	$parts = explode('/', $cidr, 2);
	if (!isset($parts[1]) || !ctype_digit($parts[1])) {
		return false;
	}
	$bin = @inet_pton($parts[0]);
	return (int)$parts[1] < (($bin !== false && strlen($bin) == 16) ? 16 : 8);
}

function webauthn_valid_cidr(string $cidr): bool {
	$parts = explode('/', $cidr, 2);
	$bin = @inet_pton($parts[0]);
	if ($bin === false) {
		return false;
	}
	return !isset($parts[1]) || (ctype_digit($parts[1]) && (int)$parts[1] <= strlen($bin) * 8);
}

/**
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
 *   from_firewall - the peer is the firewall itself (loopback, the address
 *                   the request came in on, or an interface address): a
 *                   program on the firewall, such as cloudflared, made the
 *                   connection, possibly for someone on the Internet
 * @param array<string, mixed> $server
 * @param WebAuthnSettings $settings
 * @return WebAuthnSource
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
		'from_firewall' => webauthn_is_firewall_address($peer, (string)($server['SERVER_ADDR'] ?? '')),
	];
}

/*
 * Is $ip the firewall itself? Loopback, the local address of this
 * connection ($server_addr: a connection from the firewall to itself has
 * the same address at both ends), or any configured interface address.
 * Cloudflare's private-network routing (WARP to cloudflared to a LAN IP)
 * forwards plain TCP without proxy headers, so such connections look like
 * LAN traffic from the firewall's own address (review finding F2).
 */
function webauthn_is_firewall_address(string $ip, string $server_addr): bool {
	if ($ip === '') {
		return false;
	}
	$own = ['127.0.0.0/8', '::1'];
	if ($server_addr !== '') {
		$own[] = $server_addr;
	}
	/* pfsense-utils.inc: loaded with authgui.inc, not always elsewhere. */
	foreach (['get_configured_ip_addresses', 'get_configured_ipv6_addresses'] as $fn) {
		if (function_exists($fn)) {
			foreach ($fn() as $addr) {
				if ((string)$addr !== '') {
					$own[] = (string)$addr;
				}
			}
		}
	}
	return webauthn_ip_in_list($ip, $own);
}

/**
 * May this request skip the WebAuthn step because it comes from a
 * trusted local network?
 *
 * Anything arriving through the tunnel never qualifies, even if
 * cloudflared itself sits inside a trusted network (for example on the
 * LAN or on pfSense at 127.0.0.1): otherwise every Internet user would
 * inherit the LAN's exemption. Forwarded requests are recognised by the
 * configured cloudflared address and, as a fallback when that is not
 * configured, by proxy headers such as X-Forwarded-For. Connections from
 * the firewall's own addresses never qualify either: cloudflared on the
 * firewall forwards private-network (WARP) traffic from them.
 * @param WebAuthnSettings $settings
 * @param WebAuthnSource $source
 */
function webauthn_source_is_trusted_network(array $source, array $settings): bool {
	if ($source['via_proxy'] || $source['proxy_headers'] || !empty($source['from_firewall']) || $source['peer'] === '') {
		return false;
	}
	return webauthn_ip_in_list($source['peer'], webauthn_split_list($settings['trusted_networks']));
}

/**
 * Decide what the gate does for a password-authenticated session that
 * has not yet passed WebAuthn.
 *   'skip'     - let the request through without WebAuthn
 *   'require'  - show the WebAuthn challenge
 *   'deny'     - user has no passkey and enforcement is on
 * @param WebAuthnSettings $settings
 * @param WebAuthnSource $source
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

/**
 * Where a GUI session stands with respect to the second factor.
 *   'disabled'  - the second factor is off
 *   'verified'  - passed WebAuthn in this login, recently enough, with a
 *                 passkey that is still registered, for the current RP ID
 *                 and user verification setting
 *   'revoked'   - passed WebAuthn with a passkey that has been removed
 *   'skip'      - exempt for this request (trusted network, or no passkey
 *                 while enforcement is off)
 *   'require'   - must pass WebAuthn now
 *   'deny'      - no passkey and enforcement is on
 * $session is $_SESSION.
 * @param WebAuthnSession $session
 * @param WebAuthnSettings $settings
 * @param WebAuthnSource $source
 */
function webauthn_session_status(array $settings, array $session, array $source): string {
	if (empty($settings['enable'])) {
		return 'disabled';
	}
	$user = webauthn_session_identity($session);
	if ($user === '') {
		return 'require';
	}
	$state = $session['webauthn'] ?? null;
	if (is_array($state) && ($state['method'] ?? null) === 'webauthn' &&
	    webauthn_normalize_username($state['user'] ?? '') === $user) {
		if (!is_string($state['credential'] ?? null) || webauthn_find_credential($user, $state['credential']) === null) {
			/* Its passkey was removed: the session ends, even if the user
			 * has no passkey left and would otherwise skip the step. */
			return 'revoked';
		}
		if (webauthn_verified_state_valid($state, $settings)) {
			return 'verified';
		}
		/* From another login, too old, or weaker than the settings now
		 * ask for: decide as for a session that never verified. */
	}
	$status = webauthn_gate_decision($settings, $source, webauthn_session_has_credentials($session));
	if ($status === 'skip' && webauthn_session_is_local($session) &&
	    $user !== webauthn_normalize_username($session['Username'] ?? '') &&
	    !webauthn_source_is_trusted_network($source, $settings)) {
		/* The sign-in name is not the account name it resolved to. */
		return 'require';
	}
	return $status;
}

/**
 * Is a stored passkey verification still good? It must belong to this
 * PHP session (pfSense gives every password sign-in a new session ID, so
 * a new sign-in never inherits it), be at most WEBAUTHN_VERIFIED_MAX_AGE
 * old, and match the current RP ID and user verification setting.
 * @param WebAuthnSettings $settings
 * @param array<string, mixed> $state
 */
function webauthn_verified_state_valid(array $state, array $settings): bool {
	$time = (int)($state['time'] ?? 0);
	$now = time();
	return is_string($state['sid'] ?? null) && hash_equals($state['sid'], webauthn_session_sid()) &&
	    $time > 0 && $time <= $now && $now - $time <= WEBAUTHN_VERIFIED_MAX_AGE &&
	    ($state['rp_id'] ?? null) === webauthn_rp_id($settings) &&
	    (!webauthn_require_uv($settings) || !empty($state['uv']));
}

/**
 * The session state recorded after a successful passkey verification. Call after session_regenerate_id().
 * @param WebAuthnCredential $cred
 * @param WebAuthnSettings $settings
 * @return array<string, mixed>
 */
function webauthn_verified_state(string $user, array $cred, bool $uv, array $settings): array {
	return ['user' => $user, 'method' => 'webauthn', 'credential' => (string)$cred['id'], 'time' => time(),
	    'sid' => webauthn_session_sid(), 'rp_id' => webauthn_rp_id($settings), 'uv' => $uv];
}

/**
 * Does the session's user have passkeys? For remote accounts, another
 * spelling with passkeys counts too: it must not skip the step. Without
 * intl/mbstring other spellings cannot be recognised reliably, so then
 * any passkey at all counts for remote accounts (fail closed).
 * @param WebAuthnSession $session
 */
function webauthn_session_has_credentials(array $session): bool {
	$user = webauthn_session_identity($session);
	if (!empty(webauthn_get_credentials($user))) {
		return true;
	}
	if (webauthn_session_is_local($session)) {
		return false;
	}
	if (!webauthn_unicode_available()) {
		static $warned = false;
		if (!$warned) {
			$warned = true;
			webauthn_log(LOG_WARNING, 'PHP intl/mbstring missing: every passkey counts for every LDAP/RADIUS user');
		}
		return !empty(webauthn_all_credentials());
	}
	return !empty(webauthn_case_variant_credentials($user));
}

/**
 * May this session register a passkey? Once the account (or, for remote
 * accounts, another spelling of it) has a passkey, only a session that
 * signed in with one may add another. Otherwise a password alone, from a
 * trusted network or while enforcement is off, would be enough to enrol
 * an attacker's passkey for later use through the tunnel. While the
 * second factor is off nobody is verified, so then only an admin may.
 * @param WebAuthnSession $session
 * @param WebAuthnSettings $settings
 * @param WebAuthnSource $source
 */
function webauthn_may_register(array $settings, array $session, array $source, bool $is_admin = false): bool {
	if (!webauthn_session_has_credentials($session)) {
		return true;
	}
	$status = webauthn_session_status($settings, $session, $source);
	return $status === 'verified' || ($status === 'disabled' && $is_admin);
}

/**
 * May this session remove passkey $id? Admins may always (the recovery
 * path from a trusted network). Other users may not remove their last
 * usable passkey without a session verified with a passkey: a password
 * alone would otherwise switch the passkey step off for the account.
 * For the page only; webauthn_delete_credential() decides again under
 * the config lock.
 * @param WebAuthnSession $session
 * @param WebAuthnSettings $settings
 * @param WebAuthnSource $source
 */
function webauthn_may_delete(array $settings, array $session, array $source, string $id, bool $is_admin): bool {
	if ($is_admin) {
		return true;
	}
	$rp = webauthn_rp_id($settings);
	$left = array_filter(webauthn_get_credentials(webauthn_session_identity($session)), function ($c) use ($id, $rp) {
		return ($c['id'] ?? null) !== $id && ($c['rp_id'] ?? null) === $rp;
	});
	return !empty($left) || webauthn_session_status($settings, $session, $source) === 'verified';
}

/**
 * @param WebAuthnSettings|null $settings
 */
function webauthn_rp_id(?array $settings = null): string {
	$settings = $settings ?? webauthn_settings();
	return strtolower(trim($settings['rp_id']));
}

/**
 * Origins accepted in clientDataJSON. Defaults to https://<rp_id>.
 * @param WebAuthnSettings|null $settings
 * @return list<string>
 */
function webauthn_allowed_origins(?array $settings = null): array {
	$settings = $settings ?? webauthn_settings();
	$origins = array_map('webauthn_normalize_origin', webauthn_split_list($settings['origins']));
	if (empty($origins) && webauthn_rp_id($settings) !== '') {
		$origins = ['https://' . webauthn_rp_id($settings)];
	}
	return $origins;
}

/**
 * @param WebAuthnSettings|null $settings
 */
function webauthn_require_uv(?array $settings = null): bool {
	$settings = $settings ?? webauthn_settings();
	return $settings['user_verification'] === 'required';
}

/**
 * Validate settings submitted from the GUI. Returns a list of errors.
 * @param WebAuthnSettings $s
 * @return list<string>
 */
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
	 * traffic is never exempt), but a huge network (however written, e.g.
	 * /00) would exempt or admit a large part of the Internet. */
	$trusted = webauthn_split_list($s['trusted_networks'] ?? '');
	/* A huge cloudflared source would make CF-Connecting-IP believed from
	 * anyone, so logged client addresses could be forged (finding F6). */
	foreach (['trusted_networks' => gettext('Trusted network'), 'xmlrpc_peers' => gettext('XMLRPC peer'),
	    'trusted_proxies' => gettext('cloudflared source')] as $field => $label) {
		foreach (webauthn_split_list($s[$field] ?? '') as $c) {
			if (webauthn_valid_cidr($c) && webauthn_cidr_too_large($c)) {
				$errors[] = sprintf(gettext('%1$s entry %2$s is too large: use at least /8 for IPv4 and /16 for IPv6.'),
				    $label, htmlspecialchars($c));
			}
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

/**
 * Would saving $new lock out the admin saving it, from where they are
 * ($source, under the new settings), given their passkeys $mine? Returns
 * the error message, or null.
 * @param array<WebAuthnCredential> $mine
 * @param WebAuthnSettings $new
 * @param WebAuthnSource $source
 */
function webauthn_settings_lockout_error(array $new, array $source, array $mine): ?string {
	if (empty($new['enable']) || webauthn_source_is_trusted_network($source, $new)) {
		return null;
	}
	if (webauthn_gate_decision($new, $source, !empty($mine)) == 'deny') {
		return gettext('These settings would lock you out of this session: register a passkey for your account, or save from a trusted network.');
	}
	if (!empty($mine) && !in_array(webauthn_rp_id($new), array_column($mine, 'rp_id'), true)) {
		return gettext('None of your passkeys was registered for this RP ID, so you could not sign in again: save from a trusted network, or keep the RP ID.');
	}
	return null;
}

/**
 * Log to syslog with the USER facility and a message format that does
 * not match sshguard's "webConfigurator authentication error" pattern,
 * so WebAuthn failures never add the cloudflared address (shared by all
 * tunnel users) to the GUI lockout table.
 * @param WebAuthnSource|null $source
 */
function webauthn_log(int $level, string $message, ?array $source = null): void {
	syslog(LOG_USER | $level, webauthn_log_line($message, $source));
}

/**
 * The syslog line for $message. Parts of it can come from the client (an
 * origin, an LDAP sign-in name), so it is made plain text first: one line,
 * no control or format characters (such as bidi overrides), bounded length
 * (review finding F5). The source address is added after that, so it is
 * always the last thing on the line.
 * @param WebAuthnSource|null $source
 */
function webauthn_log_line(string $message, ?array $source = null): string {
	$message = webauthn_plain($message, 400);
	if ($source !== null) {
		$message .= ' from ' . $source['client'];
		if ($source['via_proxy']) {
			$message .= ' (via cloudflared ' . $source['peer'] . ')';
		}
	}
	return 'webauthn: ' . $message;
}

/*
 * $s as one line of plain text for notices, notification e-mails and
 * config history: no control, format (e.g. bidi override) or line/paragraph
 * separator characters, valid UTF-8, at most $max characters. Login names
 * from LDAP/RADIUS can carry arbitrary text after "@".
 */
function webauthn_plain(string $s, int $max = 64): string {
	if (function_exists('mb_check_encoding') ? !mb_check_encoding($s, 'UTF-8') : !preg_match('//u', $s)) {
		$s = function_exists('mb_scrub') ? mb_scrub($s, 'UTF-8') : preg_replace('/[\x80-\xff]/', '?', $s);
	}
	$s = preg_replace('/[\x00-\x1f\x7f]/', ' ', $s);
	$s = preg_replace('/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u', ' ', $s) ?? preg_replace('/[\x80-\xff]/', '?', $s);
	if (function_exists('mb_strlen') && mb_strlen($s, 'UTF-8') > $max) {
		$s = mb_substr($s, 0, $max, 'UTF-8') . '…';
	} elseif (!function_exists('mb_strlen') && strlen($s) > $max) {
		$s = substr($s, 0, $max) . '...';
	}
	return $s;
}

/*
 * Raise a GUI notice (the bell icon; also sent through any configured
 * notification channels such as e-mail) for security-relevant events.
 * Callers quote user-supplied names ("%s"). pfSense escapes notices for
 * HTML itself (file_notice() and head.inc), so this only makes the text
 * plain. With $rate_key, at most one notice per key is raised in
 * WEBAUTHN_NOTICE_INTERVAL seconds.
 */
function webauthn_notice(string $message, ?string $rate_key = null): void {
	if ($rate_key !== null && !webauthn_notice_due($rate_key)) {
		return;
	}
	if (!function_exists('file_notice')) {
		@include_once('notices.inc');
	}
	if (function_exists('file_notice')) {
		file_notice('webauthn', webauthn_plain($message, 400), 'WebAuthn');
	}
}

/* Record that a notice for $key is raised now; false if one was raised recently. */
function webauthn_notice_due(string $key): bool {
	$due = webauthn_with_lock(WEBAUTHN_NOTICE_FILE, function () use ($key) {
		$now = time();
		$data = json_decode((string)@file_get_contents(WEBAUTHN_NOTICE_FILE), true);
		$data = is_array($data) ? $data : [];
		$data = array_filter($data, function ($t) use ($now) {
			return is_int($t) && $t > $now - WEBAUTHN_NOTICE_INTERVAL;
		});
		$k = hash('sha256', $key);
		if (isset($data[$k])) {
			return false;
		}
		$data[$k] = $now;
		if (webauthn_write_json(WEBAUTHN_NOTICE_FILE, $data)) {
			return true;
		}
		/* /conf cannot be written (full disk): rate limit with a marker in
		 * WEBAUTHN_RUN_DIR instead; without one, raise no notice at all
		 * rather than one per request. */
		return webauthn_run_marker_due('notice_' . substr($k, 0, 32));
	}, null);
	return $due ?? webauthn_run_marker_due('notice_' . substr(hash('sha256', $key), 0, 32));
}

/* True (and the marker set) if marker $name in WEBAUTHN_RUN_DIR is absent or older than WEBAUTHN_NOTICE_INTERVAL. */
function webauthn_run_marker_due(string $name): bool {
	$f = WEBAUTHN_RUN_DIR . '/webauthn_' . $name;
	clearstatcache(true, $f);
	if (file_exists($f) && time() - (int)@filemtime($f) < WEBAUTHN_NOTICE_INTERVAL) {
		return false;
	}
	return @touch($f);
}

/*
 * Is $name acceptable as a passkey name? Letters, digits, spaces and
 * . _ ( ) - only, 1 to 64 characters, valid UTF-8: config.xml must stay
 * readable (pfSense writes control characters into it unchanged, which
 * makes the file invalid XML).
 */
function webauthn_valid_passkey_name(string $name): bool {
	return preg_match('//u', $name) === 1 && preg_match('/^[\p{L}\p{N} ._()\-]{1,64}$/u', $name) === 1;
}
