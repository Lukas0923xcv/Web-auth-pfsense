<?php
/*
 * storage.inc
 *
 * Passkey storage for the WebAuthn second factor: credential records in
 * config.xml, safe config updates, revocation list, signature counters,
 * and the file locking and atomic writes they rely on.
 *
 * Licensed under the Apache License, Version 2.0.
 */

/* Loaded by webauthn.inc, which defines the constants used here. */

/**
 * All stored credentials as a list, without revoked ones. <item> is a
 * pfSense list tag, so it always parses as a list; wrap a bare element
 * anyway in case one was written by hand.
 * @return list<WebAuthnCredential>
 */
function webauthn_all_credentials(): array {
	$all = config_get_path(WEBAUTHN_CRED_PATH, []);
	if (!is_array($all)) {
		return [];
	}
	if (isset($all['id']) && !is_array($all['id'])) {
		$all = [$all];
	}
	/* A damaged list still lets every passkey count as present (no skipping); webauthn_find_credential() then refuses them all. */
	$revoked = webauthn_revoked_ids() ?? [];
	return array_values(array_filter($all, function ($c) use ($revoked) {
		return is_array($c) && !webauthn_is_revoked($c, $revoked);
	}));
}

/**
 * Credentials of $username (all if null). Passkeys registered by a local
 * account record its uid; once that account is deleted and a new one
 * gets the same name, they no longer count (see webauthn_orphaned()).
 * @return list<WebAuthnCredential>
 */
function webauthn_get_credentials(?string $username = null): array {
	$out = [];
	foreach (webauthn_all_credentials() as $c) {
		if ($username === null || (webauthn_normalize_username($c['username'] ?? '') === webauthn_normalize_username($username) &&
		    !webauthn_orphaned($c))) {
			$out[] = $c;
		}
	}
	return $out;
}

/**
 * Was $c registered by a local account that no longer exists (same name, other uid, or gone)?
 * @param WebAuthnCredential $c
 */
function webauthn_orphaned(array $c): bool {
	if (!isset($c['uid']) || $c['uid'] === '') {
		return false;
	}
	$u = webauthn_local_user(webauthn_normalize_username($c['username'] ?? ''));
	return !is_array($u) || (string)($u['uid'] ?? '') !== (string)$c['uid'];
}

/*
 * Change installedpackages/webauthn safely: under our own lock, on the
 * configuration as it is on disk now (pfSense keeps the config as it was
 * when the request started, and write_config() writes all of it, so a
 * change made by a parallel request would otherwise be undone). $change
 * returns false to abort. pfSense's own config lock (/tmp/config.lock) is
 * a different file, taken inside write_config(): no deadlock.
 */
function webauthn_config_update(callable $change, string $desc, ?callable $after = null): bool {
	return webauthn_with_lock(WEBAUTHN_CONFIG_LOCK, function () use ($change, $desc, $after) {
		if (!webauthn_config_reload() || $change() === false) {
			return false;
		}
		if (!is_array(write_config(webauthn_plain($desc, 200)))) {
			return false;
		}
		webauthn_record_config_state();
		/* Still under the lock, so it cannot interleave with another change. */
		return $after === null || $after() !== false;
	}, false);
}

/**
 * Hash of the package's part of a config ($section, default: in memory).
 * Normalised as config.xml stores it: empty lists dropped, values as
 * strings, so a save and its re-read hash alike.
 * @param mixed $section
 */
function webauthn_config_hash($section = null): string {
	$norm = function ($v) use (&$norm) {
		if (!is_array($v)) {
			return (string)$v;
		}
		$out = [];
		foreach ($v as $k => $x) {
			$x = $norm($x);
			if ($x !== []) {
				$out[(string)$k] = $x;
			}
		}
		return $out;
	};
	$section = func_num_args() ? $section : config_get_path('installedpackages/webauthn', []);
	return hash('sha256', serialize($norm(is_array($section) ? $section : [])));
}

/**
 * The package's part of config.xml as it is on disk now; null if it cannot be read.
 * @return array<mixed>|null
 */
function webauthn_disk_section(): ?array {
	if (!function_exists('parse_xml_config') || !function_exists('g_get')) {
		return null;
	}
	$parsed = parse_xml_config(g_get('conf_path') . '/config.xml', [g_get('xml_rootobj')]);
	if (!is_array($parsed)) {
		return null;
	}
	$section = $parsed['installedpackages']['webauthn'] ?? [];
	return is_array($section) ? $section : [];
}

/* Remember the package's config as saved now. */
function webauthn_record_config_state(): bool {
	return webauthn_write_json(WEBAUTHN_STATE_FILE, ['hash' => webauthn_config_hash(), 'time' => time()]);
}

/*
 * Did installedpackages/webauthn change since this package last saved it?
 * Other pages save the whole config as it was when their request began,
 * so a save overlapping a passkey or settings change can undo it (removed
 * passkeys stay revoked regardless); a config restore changes it too.
 * Neither can be prevented from here, but neither stays silent: the first
 * request that sees the difference raises a notice and records the new
 * state. Returns true if a difference was found.
 */
function webauthn_check_config_state(): bool {
	$data = json_decode((string)@file_get_contents(WEBAUTHN_STATE_FILE), true);
	if (is_array($data) && ($data['hash'] ?? null) === webauthn_config_hash()) {
		return false;
	}
	/* The state could not be recorded recently (full /conf): do not parse
	 * config.xml under the lock on every request; try again later. */
	$retry = WEBAUTHN_RUN_DIR . '/webauthn_state_retry';
	clearstatcache(true, $retry);
	if (file_exists($retry) && time() - (int)@filemtime($retry) < WEBAUTHN_NOTICE_INTERVAL) {
		return false;
	}
	$changed = webauthn_with_lock(WEBAUTHN_CONFIG_LOCK, function () use ($retry) {
		$data = json_decode((string)@file_get_contents(WEBAUTHN_STATE_FILE), true);
		$known = is_array($data) && isset($data['hash']);
		/* This request may simply have loaded the config before the last
		 * save by this package: compare what is on disk now. */
		$disk = webauthn_disk_section();
		$now = $disk === null ? webauthn_config_hash() : webauthn_config_hash($disk);
		if ($known && $data['hash'] === $now) {
			return false;
		}
		if (!webauthn_write_json(WEBAUTHN_STATE_FILE, ['hash' => $now, 'time' => time()])) {
			@touch($retry);
		}
		return $known;
	}, false);
	if ($changed) {
		webauthn_log(LOG_WARNING, 'passkeys or settings changed outside the WebAuthn page (config restore, or another page saving an older copy)');
		webauthn_notice('The WebAuthn passkeys or settings changed outside System > WebAuthn Passkeys: a config restore, ' .
		    'or another page saving an older copy of the configuration at the same time. Check that the settings and passkeys are as intended.',
		    'config-state');
	}
	return $changed;
}

/*
 * Reload config.xml into memory. Newer pfSense has config_read_file();
 * older versions (2.7.x) only parse_config(), which can die() or restore
 * a backup, so there config.xml is parsed directly. False (abort the
 * change) if the file cannot be read.
 */
function webauthn_config_reload(): bool {
	if (function_exists('config_read_file')) {
		return config_read_file(false, false);
	}
	if (!function_exists('parse_xml_config') || !function_exists('g_get')) {
		return false;
	}
	$parsed = parse_xml_config(g_get('conf_path') . '/config.xml', [g_get('xml_rootobj')]);
	if (!is_array($parsed) || empty($parsed)) {
		return false;
	}
	$GLOBALS['config'] = $parsed;
	return true;
}

/**
 * Store a new passkey. Returns null on success, or an error message.
 * $uid: the pfSense uid of a local account, '' for remote accounts.
 * @param array{credential_id: string, alg: int, pem: string, sign_count: int, uv: bool} $reg
 */
function webauthn_add_credential(string $username, string $name, array $reg, string $rp_id, string $uid = ''): ?string {
	$id = webauthn_b64url_encode($reg['credential_id']);
	$error = null;
	$ok = webauthn_config_update(function () use ($username, $name, $reg, $rp_id, $uid, $id, &$error) {
		$all = config_get_path(WEBAUTHN_CRED_PATH, []);
		$all = is_array($all) ? array_values(array_filter(isset($all['id']) && !is_array($all['id']) ? [$all] : $all, 'is_array')) : [];
		$revoked = webauthn_revoked_ids();
		if ($revoked === null) {
			$error = gettext('The list of removed passkeys is damaged; see the system log.');
			return false;
		}
		$new_key = webauthn_public_key_hash(base64_encode($reg['pem']));
		$entry = $revoked[$id] ?? null;
		if ($entry !== null && (!is_array($entry) || in_array($new_key, (array)($entry['keys'] ?? []), true))) {
			/* The same key under the same ID is the removed passkey itself
			 * (or a copy of it); a whole-ID revocation (older versions)
			 * cannot tell keys apart. Neither comes back. */
			$error = gettext('This passkey was removed earlier and cannot be registered again.');
			return false;
		}
		$own = 0;
		foreach ($all as $i => $c) {
			if (($c['id'] ?? null) === $id) {
				if (!webauthn_is_revoked($c, $revoked)) {
					$error = gettext('This passkey is already registered.');
					return false;
				}
				/* A revoked record brought back (e.g. by a restore) is replaced. */
				unset($all[$i]);
			} elseif (!webauthn_is_revoked($c, $revoked) && !webauthn_orphaned($c) &&
			    webauthn_normalize_username($c['username'] ?? '') === webauthn_normalize_username($username)) {
				$own++;
			}
		}
		if ($own >= WEBAUTHN_MAX_CREDENTIALS_PER_USER) {
			$error = sprintf(gettext('An account can have at most %d passkeys.'), WEBAUTHN_MAX_CREDENTIALS_PER_USER);
			return false;
		}
		$all = array_values($all);
		/* Stored before the passkey becomes usable: a counter that cannot
		 * be kept would make clone detection meaningless. */
		if (!webauthn_set_sign_count($id, (int)$reg['sign_count'])) {
			$error = gettext('The signature counter could not be stored.');
			return false;
		}
		$rec = [
			'username' => webauthn_normalize_username($username),
			'name' => $name,
			'id' => $id,
			'alg' => (string)$reg['alg'],
			'publickey' => base64_encode($reg['pem']),
			'rp_id' => $rp_id,
			'created' => (string)time(),
		];
		if ($uid !== '') {
			$rec['uid'] = $uid;
		}
		$all[] = $rec;
		config_set_path(WEBAUTHN_CRED_PATH, $all);
	}, sprintf('WebAuthn: registered passkey "%s" for user "%s"', webauthn_plain($name), webauthn_plain($username)));
	if (!$ok) {
		return $error ?? gettext('The configuration could not be saved.');
	}
	return null;
}

/*
 * Delete a credential; restrict to $username unless null (admin). Every
 * matching record with that ID goes, and its key is revoked first, so it
 * is never accepted again even if the change cannot be saved or a config
 * restore brings it back. Unless $may_remove_last, the account must keep another
 * usable passkey (for the current RP ID). All of it is decided under the
 * config lock on the reloaded config, so parallel removals cannot each
 * leave the other passkey as "the one left". True only if the change was
 * saved and the ID is gone; $error says why not.
 */
function webauthn_delete_credential(string $id, ?string $username = null, bool $may_remove_last = true, ?string &$error = null): bool {
	$error = null;
	$match = function ($c) use ($id, $username) {
		return is_array($c) && ($c['id'] ?? null) === $id && ($username === null ||
		    webauthn_normalize_username($c['username'] ?? '') === webauthn_normalize_username($username));
	};
	$ok = webauthn_config_update(function () use ($id, $username, $may_remove_last, $match, &$error) {
		if (empty(array_filter(webauthn_all_credentials(), $match))) {
			$error = gettext('Passkey not found.');
			return false;
		}
		if (!$may_remove_last && $username !== null) {
			$rp = webauthn_rp_id(webauthn_settings());
			$left = array_filter(webauthn_get_credentials($username), function ($c) use ($id, $rp) {
				return ($c['id'] ?? null) !== $id && ($c['rp_id'] ?? null) === $rp;
			});
			if (empty($left)) {
				$error = gettext('This is your last usable passkey: sign in with it (through a non-trusted path) before removing it, or ask an administrator.');
				return false;
			}
		}
		$all = config_get_path(WEBAUTHN_CRED_PATH, []);
		$all = is_array($all) ? (isset($all['id']) && !is_array($all['id']) ? [$all] : $all) : [];
		$keys = [];
		foreach ($all as $c) {
			if ($match($c)) {
				$keys[] = webauthn_public_key_hash((string)($c['publickey'] ?? ''));
			}
		}
		if (!webauthn_revoke($id, $keys)) {
			$error = gettext('The passkey could not be revoked. Check the system log.');
			return false;
		}
		$keep = [];
		foreach ($all as $c) {
			if (is_array($c) && !$match($c)) {
				$keep[] = $c;
			}
		}
		config_set_path(WEBAUTHN_CRED_PATH, $keep);
	}, 'WebAuthn: removed passkey ' . substr($id, 0, 16), function () use ($id) {
		if (!webauthn_config_reload()) {
			return false;
		}
		foreach ((array)config_get_path(WEBAUTHN_CRED_PATH, []) as $c) {
			if (is_array($c) && ($c['id'] ?? null) === $id) {
				return false;
			}
		}
	});
	if (!$ok) {
		$error = $error ?? gettext('The passkey could not be removed. Check the system log.');
		return false;
	}
	webauthn_with_lock(WEBAUTHN_COUNTER_FILE, function () use ($id) {
		$data = webauthn_read_counters();
		if (is_array($data) && isset($data[$id])) {
			unset($data[$id]);
			webauthn_write_json(WEBAUTHN_COUNTER_FILE, $data);
		}
	});
	return true;
}

/**
 * Save the settings under the config lock.
 * @param WebAuthnSettings $new
 */
function webauthn_save_settings(array $new): bool {
	return webauthn_config_update(function () use ($new) {
		config_set_path(WEBAUTHN_CONFIG_PATH, $new);
	}, gettext('WebAuthn: settings changed'));
}

/**
 * Removed passkeys: credential ID => ['t' => time, 'keys' => hashes of
 * the public keys removed under that ID] (a bare time, written by older
 * versions, revokes every key under the ID). Null if the file exists but
 * cannot be read as such (it is only ever replaced whole, so this means
 * outside damage): then no passkey is accepted (fail closed).
 *
 * Revocation is by ID and key: registering the same ID again with a new
 * key, under any account, never makes a removed record valid again, even
 * when a config restore brings that record back.
 * @return array<mixed>|null
 */
function webauthn_revoked_ids(): ?array {
	$raw = @file_get_contents(WEBAUTHN_REVOKED_FILE);
	if ($raw === false) {
		return file_exists(WEBAUTHN_REVOKED_FILE) ? null : [];
	}
	$data = json_decode($raw, true);
	return is_array($data) ? $data : null;
}

function webauthn_public_key_hash(string $publickey): string {
	return hash('sha256', $publickey);
}

/**
 * Is stored record $c revoked according to $revoked (webauthn_revoked_ids())?
 * @param WebAuthnCredential $c
 * @param array<mixed> $revoked
 */
function webauthn_is_revoked(array $c, array $revoked): bool {
	$entry = $revoked[(string)($c['id'] ?? '')] ?? null;
	if ($entry === null) {
		return false;
	}
	return !is_array($entry) || in_array(webauthn_public_key_hash((string)($c['publickey'] ?? '')), (array)($entry['keys'] ?? []), true);
}

/**
 * Revoke the keys $keys (public key hashes) under credential ID $id.
 * @param array<string> $keys
 */
function webauthn_revoke(string $id, array $keys): bool {
	return webauthn_with_lock(WEBAUTHN_REVOKED_FILE, function () use ($id, $keys) {
		$data = webauthn_revoked_ids();
		if ($data === null) {
			return false;
		}
		$old = $data[$id] ?? null;
		if ($old !== null && !is_array($old)) {
			/* Already revoked for every key. */
			return true;
		}
		$data[$id] = ['t' => time(), 'keys' => array_values(array_unique(array_merge((array)($old['keys'] ?? []), $keys)))];
		return webauthn_write_json(WEBAUTHN_REVOKED_FILE, $data);
	});
}

/**
 * Signature counters are kept outside config.xml so that every login
 * does not create a configuration revision. A damaged counter file is
 * not read as empty (that would reset every counter): counters are then
 * neither checked nor stored, so passkey sign-ins fail until it is
 * repaired or removed.
 * @return array<mixed>|null
 */
function webauthn_read_counters(): ?array {
	$raw = @file_get_contents(WEBAUTHN_COUNTER_FILE);
	if ($raw === false) {
		return file_exists(WEBAUTHN_COUNTER_FILE) ? null : [];
	}
	$data = json_decode($raw, true);
	if (!is_array($data)) {
		static $logged = false;
		if (!$logged) {
			$logged = true;
			webauthn_log(LOG_ERR, WEBAUTHN_COUNTER_FILE . ' is damaged: passkey sign-ins fail until it is repaired or removed');
		}
		return null;
	}
	return $data;
}

function webauthn_get_sign_count(string $id): int {
	return (int)(webauthn_read_counters()[$id] ?? 0);
}

function webauthn_set_sign_count(string $id, int $count): bool {
	return webauthn_with_lock(WEBAUTHN_COUNTER_FILE, function () use ($id, $count) {
		$data = webauthn_read_counters();
		if ($data === null) {
			return false;
		}
		$data[$id] = $count;
		return webauthn_write_json(WEBAUTHN_COUNTER_FILE, $data);
	});
}

/*
 * Atomically advance the counter; false if it did not increase or could
 * not be stored. Comparing against the value on disk under the lock means
 * two parallel assertions (a clone and the real key) cannot both pass
 * and leave the counter lower than one of them reported.
 */
function webauthn_advance_sign_count(string $id, int $count): bool {
	return webauthn_with_lock(WEBAUTHN_COUNTER_FILE, function () use ($id, $count) {
		$data = webauthn_read_counters();
		if ($data === null) {
			return false;
		}
		$stored = (int)($data[$id] ?? 0);
		if (($count != 0 || $stored != 0) && $count <= $stored) {
			return false;
		}
		$data[$id] = $count;
		return webauthn_write_json(WEBAUTHN_COUNTER_FILE, $data);
	}, false);
}

/**
 * Run $fn holding an exclusive lock on "$file.lock"; $fail if the lock cannot be taken.
 * @param mixed $fail
 * @return mixed
 */
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

/**
 * Replace $file with $data as JSON through a temp file of this process
 * and rename, so a failed write (e.g. a full disk) never leaves a
 * truncated file behind. The file is mode 0600.
 * @param array<mixed> $data
 */
function webauthn_write_json(string $file, array $data): bool {
	$json = json_encode($data);
	if (!is_string($json)) {
		return false;
	}
	$tmp = $file . '.' . getmypid() . '.tmp';
	@unlink($tmp);
	$old = umask(077);
	$fp = @fopen($tmp, 'x');
	umask($old);
	$ok = $fp !== false && fwrite($fp, $json) === strlen($json);
	if ($fp !== false) {
		$ok = fclose($fp) && $ok;
	}
	$ok = $ok && @chmod($tmp, 0600) && @rename($tmp, $file);
	if (!$ok) {
		@unlink($tmp);
	}
	return $ok;
}

/**
 * Find a usable stored credential for $username by its base64url ID.
 * @return WebAuthnCredential|null
 */
function webauthn_find_credential(string $username, string $id): ?array {
	if (webauthn_revoked_ids() === null) {
		static $logged = false;
		if (!$logged) {
			$logged = true;
			webauthn_log(LOG_ERR, WEBAUTHN_REVOKED_FILE . ' is damaged: no passkey is accepted until it is repaired or removed');
		}
		return null;
	}
	foreach (webauthn_get_credentials($username) as $c) {
		if (hash_equals((string)$c['id'], $id)) {
			$c['pem'] = base64_decode($c['publickey']);
			$c['sign_count'] = webauthn_get_sign_count($c['id']);
			return $c;
		}
	}
	return null;
}

/**
 * Failed passkey attempts per account and client address, kept in
 * WEBAUTHN_FAILURE_FILE so that a new session or another password login
 * cannot reset them: key => ['n' => attempts, 't' => time of the last
 * one, 'u' => account hash]. An entry expires WEBAUTHN_FAILURE_WINDOW
 * seconds after its last attempt. Null if the file is damaged: then every
 * account counts as locked (fail closed) until the file is repaired or
 * removed.
 *
 * The hard limit is per client address (IPv6: per /64), not for the
 * whole account: anyone who knows the password could otherwise keep the
 * real user locked out by failing on purpose (review finding F1). Over all
 * addresses, an account with WEBAUTHN_MAX_ACCOUNT_FAILURES failures in the
 * window is throttled to one attempt per WEBAUTHN_ACCOUNT_THROTTLE seconds,
 * so changing addresses does not give unlimited attempts either.
 * @return array<string, array{n: int, t: int, u: string}>|null
 */
function webauthn_read_failures(int $now): ?array {
	$raw = @file_get_contents(WEBAUTHN_FAILURE_FILE);
	if ($raw === false) {
		return file_exists(WEBAUTHN_FAILURE_FILE) ? null : [];
	}
	$data = json_decode($raw, true);
	$valid = is_array($data);
	foreach ($valid ? $data : [] as $e) {
		$valid = $valid && is_array($e) && is_int($e['n'] ?? null) && is_int($e['t'] ?? null) && is_string($e['u'] ?? null);
	}
	if (!$valid) {
		static $logged = false;
		if (!$logged) {
			$logged = true;
			webauthn_log(LOG_ERR, WEBAUTHN_FAILURE_FILE . ' is damaged: passkey sign-ins are refused until it is repaired or removed');
		}
		return null;
	}
	return array_filter($data, function ($e) use ($now) {
		return $e['t'] > $now - WEBAUTHN_FAILURE_WINDOW;
	});
}

function webauthn_failure_user_hash(string $user): string {
	return substr(hash('sha256', webauthn_normalize_username($user)), 0, 32);
}

function webauthn_failure_key(string $user, string $client): string {
	return substr(hash('sha256', webauthn_normalize_username($user) . "\0" . webauthn_failure_address($client)), 0, 32);
}

/* The address attempts are counted under: IPv4 as it is, IPv6 by its /64 (one host usually has a whole /64). */
function webauthn_failure_address(string $client): string {
	$bin = @inet_pton($client);
	if ($bin === false || strlen($bin) != 16) {
		return $client;
	}
	return inet_ntop(substr($bin, 0, 8) . str_repeat("\0", 8)) . '/64';
}

/**
 * The account-wide picture: attempts from all addresses in the window, and
 * the time of the latest.
 * @param array<string, array{n: int, t: int, u: string}> $data
 * @return array{0: int, 1: int}
 */
function webauthn_failure_account(array $data, string $user): array {
	$total = 0;
	$last = 0;
	foreach ($data as $e) {
		if ($e['u'] === webauthn_failure_user_hash($user)) {
			$total += $e['n'];
			$last = max($last, $e['t']);
		}
	}
	return [$total, $last];
}

/**
 * Seconds until the account takes another attempt under the account-wide throttle; 0 if it does now.
 * @param array<string, array{n: int, t: int, u: string}> $data
 */
function webauthn_failure_throttle_remaining(array $data, string $user, int $now): int {
	[$total, $last] = webauthn_failure_account($data, $user);
	if ($total < WEBAUTHN_MAX_ACCOUNT_FAILURES || $now - $last >= WEBAUTHN_ACCOUNT_THROTTLE) {
		return 0;
	}
	return max(1, $last + WEBAUTHN_ACCOUNT_THROTTLE - $now);
}

/*
 * Seconds until $user may try a passkey again from $client (the address
 * lock or the account-wide throttle); 0 if they may now. A damaged attempt
 * list counts as locked for the whole window.
 */
function webauthn_failure_lock_remaining(string $user, string $client): int {
	$now = time();
	$data = webauthn_read_failures($now);
	if ($data === null) {
		return WEBAUTHN_FAILURE_WINDOW;
	}
	$throttle = webauthn_failure_throttle_remaining($data, $user, $now);
	$e = $data[webauthn_failure_key($user, $client)] ?? null;
	if ($e === null || $e['n'] < WEBAUTHN_MAX_USER_FAILURES) {
		return $throttle;
	}
	return max($throttle, 1, $e['t'] + WEBAUTHN_FAILURE_WINDOW - $now);
}

/* Failed attempts for $user from all addresses in the window (for the notice). */
function webauthn_failure_account_total(string $user): int {
	return webauthn_failure_account(webauthn_read_failures(time()) ?? [], $user)[0];
}

/*
 * Count a passkey attempt for $user from $client before it is verified;
 * a successful one is uncounted again by webauthn_failure_clear().
 * Counting first means a failure needs no write: if the attempt cannot be
 * recorded (the list is damaged, /conf is full, the lock cannot be taken)
 * or the limit is used up, this returns false and the attempt must not be
 * verified at all (fail closed).
 */
function webauthn_failure_begin(string $user, string $client): bool {
	return webauthn_with_lock(WEBAUTHN_FAILURE_FILE, function () use ($user, $client) {
		$now = time();
		$data = webauthn_read_failures($now);
		if ($data === null) {
			return false;
		}
		$k = webauthn_failure_key($user, $client);
		$n = $data[$k]['n'] ?? 0;
		if ($n >= WEBAUTHN_MAX_USER_FAILURES || webauthn_failure_throttle_remaining($data, $user, $now) > 0) {
			return false;
		}
		$data[$k] = ['n' => $n + 1, 't' => $now, 'u' => webauthn_failure_user_hash($user)];
		return webauthn_write_json(WEBAUTHN_FAILURE_FILE, $data);
	}, false);
}

/* Forget $user's attempts from $client after a successful passkey sign-in there. */
function webauthn_failure_clear(string $user, string $client): void {
	webauthn_with_lock(WEBAUTHN_FAILURE_FILE, function () use ($user, $client) {
		$k = webauthn_failure_key($user, $client);
		$data = webauthn_read_failures(time());
		if ($data === null || !isset($data[$k])) {
			return;
		}
		unset($data[$k]);
		if (!webauthn_write_json(WEBAUTHN_FAILURE_FILE, $data)) {
			/* Only means this success still counts as one attempt. */
			webauthn_log(LOG_WARNING, 'could not update ' . WEBAUTHN_FAILURE_FILE);
		}
	});
}
