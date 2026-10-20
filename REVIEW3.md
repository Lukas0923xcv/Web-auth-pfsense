# Third security review: pfSense WebAuthn second factor

Commit reviewed: `cccbb093998608bb382acb8ff60cf36ea609f823`.

pfSense was checked against `pfsense/pfsense` master (`9363ac5`), because the public mirror has no 2.8.1 tag. The repository fixtures `authgui.inc`, `auth_check.inc` and `xmlrpc.php` match master byte for byte.

Tests:
- Existing suites: `tests/run.php` 79/79, `tests/gate_test.php` 14/14, `tests/audit_test.php` 50/50.
- Tests in `tests/review3/`. Before the fixes, each one failed as described below.

```
php tests/review3/review3_test.php       # R1 R2 R4 R5 R7 R10
php tests/review3/gate_ldap_variant.php  # R1 end to end through webauthn_gate()
sh  tests/review3/hook_enospc.sh       # R3 (root: mounts a 64 KiB tmpfs)
php tests/review3/fuzz_parsers.php     # CBOR/authData/COSE mutation fuzz (passes)
```

## Status

All findings below are fixed in the commit that adds this file, except where noted. Each fix has a regression test in `tests/review3/`.

| Finding | Fix |
|---|---|
| R1 LDAP spellings skip the passkey | `webauthn_username_fold()` drops `@…`/`\…`, applies NFKC, collapses spaces and lower-cases (UTF-8). Another spelling with passkeys counts as "has passkeys" for remote (non-local) sessions. |
| R2 removing the last passkey does not revoke | New status `revoked`: the gate signs the session out, and `auth_check.inc` ignores its cached privileges. |
| R3 empty `authgui.inc` on a full disk | `replace_file()` writes a per-process temp file, checks the write, fsyncs, reads it back, lints, then renames. Uninstall uses the same path. |
| R4 enrolment through another spelling | `webauthn_may_register()` uses the same "has passkeys" rule as the gate. |
| R5 XMLRPC from the LAN | While enabled, XMLRPC is accepted only from trusted networks and the new **XMLRPC peers** setting. HA users must add the partner's address. |
| R6 silent fail-open after upgrades | Hooks are also re-applied from `<earlyshellcmd>` (before the GUI starts). A failed patch raises a GUI notice once per boot. `status` reports the boot command. |
| R7 nonce list loss | List moved to `/conf`, written via temp file and rename. A damaged list refuses logins until every challenge it could hold has expired. |
| R8 `/status` through the tunnel | README ingress example blocks it. Cannot be fixed in pfSense from the package. |
| R9 concurrent `ensure` | Per-process temp name and a lock on `/var/run/webauthn_hook.lock`. An `ensure` queued behind an uninstall does nothing. |
| R10 local `Bob`/`bob` lockout | The spelling rule applies only to LDAP/RADIUS sessions; local names stay exact. |
| Key file race | Created via temp file and `link()`; the first writer wins. Counter file written atomically too. |
| Single trusted IP, RP ID change, notice flooding | Not changed. The README now warns about single addresses on a shared LAN. |

## Confirmed

### R1. LDAP username variants skip the passkey of the real account (High; needs LDAP auth and Enforce off)

pfSense's `ldap_backed()` and `ldap_get_groups()` (`etc/inc/auth.inc` 1536-1543 and 1351-1359) cut the login name at `@` (unless `ldap_nostrip_at`) and at `\`. `ldap_escape()` runs only after that. `session_auth()` then stores the typed name unchanged: `$_SESSION['Username'] = $_POST['usernamefld']` (auth.inc 2229). The directory also matches `uid`/`sAMAccountName` case-insensitively, after Unicode (NFKC) and space normalisation.

Exploit (threat a): sign in through the tunnel as `admin@x`, `admin\x`, `ADMIN@corp`, `admin<NBSP>` or `ａdmin`, using admin's password.
1. LDAP binds as `admin`.
2. `getAllowedPages()` takes admin's LDAP groups (priv.inc 249, through the same stripping).
3. `webauthn_session_status()` finds no credential for the exact name.
4. `webauthn_case_variant_credentials()` only lower-cases ASCII, so `admin@x` is not seen as a variant of `admin`.
5. `webauthn_gate_decision()` returns `skip`. The result is full admin with no passkey, although `admin` has passkeys.

The README promises the opposite for case variants. With Enforce on the result is `deny`, so there is no bypass. RADIUS servers that strip realms or fold case behave the same way.

Fix: compare credential owners with a folding key that is at least as loose as any backend. The exact match stays for passkey ownership; the folded match only ever adds "has passkeys":

```php
function webauthn_username_fold(?string $u): string {
	$u = explode('\\', explode('@', (string)$u, 2)[0], 2)[0];
	if (class_exists('Normalizer')) {
		$u = Normalizer::normalize($u, Normalizer::FORM_KC);
	}
	return mb_strtolower(trim(preg_replace('/[\p{Z}\s]+/u', ' ', $u)), 'UTF-8');
}
```

Stripping unconditionally can only turn `skip` into the "use the registered spelling" page, never the reverse. Also tell LDAP and RADIUS users to turn Enforce on.

### R2. Removing a user's last passkey does not revoke the sessions it verified (Medium)

`webauthn_session_status()` drops the `verified` state when the credential is gone. It then falls through to `webauthn_gate_decision()`. When the user has no passkeys left and Enforce is off, that returns `skip`. The gate stores `method = no-credential` and lets the session through. `auth_check.inc` keeps honouring its cached privileges.

Scenario: an admin notices a stolen verified session and removes the passkey to cut it off. The stolen session keeps working. This contradicts the README ("Removing a passkey ends the sessions it verified").

Fix: when `state.method === 'webauthn'` and the credential is gone, return a `revoked` status. The gate then calls `webauthn_gate_logout()`, and `webauthn_cached_privileges_allowed()` returns false.

### R3. Disk full while the hook is written leaves `authgui.inc` empty, which removes all GUI authentication (High impact, low likelihood)

`patch_target()` (hook.php 145-154) does not check the result of `file_put_contents($tmp, $new)`. `php -l` reports "No syntax errors" for an empty or truncated file. The function then renames the tmp file over the target, logs "hook installed" and returns true.

`guiconfig.inc` does `require_once("authgui.inc")`. With an empty file every GUI page, including `diag_command.php`, runs with no login. Every later `ensure` finds no anchor in the empty file and leaves it as it is, so the failure is permanent.

Reproduced on a real full tmpfs (`tests/review3/hook_enospc.sh`):
`patch_target returned true; authgui.inc 12343 -> 0 bytes`.

The risk is highest right after a pfSense upgrade, when `ensure` must rewrite the file and the disk is often nearly full. `unpatch_all()` writes the target in place without a temp file, and is exposed the same way. An empty `auth_check.inc` likewise opens `getstats.php` and similar endpoints.

Fix: write, read back, compare, and only then rename:

```php
if (file_put_contents($tmp, $new) !== strlen($new) || file_get_contents($tmp) !== $new) {
	@unlink($tmp);
	fwrite(STDERR, "Could not write {$tmp}; {$file} left unchanged\n");
	return false;
}
```

Use the same tmp-plus-rename path in `unpatch_all()`. Use a per-process tmp name (`.webauthn-tmp-<pid>.orig`) and hold an `flock` on `/var/run/webauthn_hook.lock` (see R9).

### R4. The "second passkey needs a passkey session" rule is bypassed by a name variant on a trusted network (Low)

`system_webauthn.php` 34-35 checks only `webauthn_get_credentials($username)` for the exact name. On a trusted network, `Admin` or `admin@x` (LDAP, the same person) has no passkeys of its own, so it may enrol one. That passkey then works through the tunnel as `Admin`, even with Enforce on, because it is an exact-name passkey.

The attacker already holds admin rights on the trusted network, and the README calls this rule a speed bump. But the bypass turns a LAN foothold into a lasting Internet credential, and the only trace is a notice.

Fix: `$may_register` should also require a verified session when `webauthn_case_variant_credentials()` (with the R1 folding) is not empty.

### R5. XMLRPC from the LAN needs only the password (documented, but defeats threat b)

`xmlrpc.php` exposes `exec_shell`, `exec_php` and `restore_config_section` (lines 138-182). Any LAN host outside the trusted networks that knows the admin password gets root, and can switch WebAuthn off.

The README lists this under "not covered", but it fully defeats threat model (b). The guard refuses only proxied requests.

Fix: while WebAuthn is enabled, refuse XMLRPC unless the peer is in the trusted networks or in a new "XMLRPC peers" setting (the HA partner's sync address).

### R6. Silent fail-open after upgrades or anchor drift (Medium; documented)

Several paths leave the hook out with only a syslog line:
- An anchor mismatch logs only to syslog.
- The first boot after an upgrade or a config restore skips `rc.start_packages` (`/cf/conf/needs_package_sync`, pfSense-rc 511-516). That leaves up to 5 minutes until cron runs.
- A restored config that lacks the cron item loses the periodic re-apply.

Fixes:
- Also add `/usr/local/bin/php -f /usr/local/pkg/webauthn/hook.php ensure` to `system/earlyshellcmd`. `rc.bootup` runs it at line 202, before `system_webgui_start()` at line 381, and after the stage-2 base upgrade.
- Raise `file_notice()` when patching fails, not just a syslog line.

## Theoretical / hardening

- **R7, replay after the used-nonce list is lost (Low).** `webauthn_mark_nonce_used()` treats a missing or corrupt `/var/run` file as "nothing used". A disk-full error between `ftruncate` and `fwrite`, or a reboot inside the 5-minute window, makes a challenge reusable. For zero-counter authenticators (iCloud, Google) the nonce is the only replay barrier. Exploiting it also needs the victim's session cookie. Fix: write to a temp file and rename it; refuse if the file is non-empty but not valid JSON.
- **R8, `/status` through the tunnel (Low, info leak).** With cloudflared on pfSense (`127.0.0.1`, the README's example), nginx's localhost-only `location ~ ^/status$` serves php-fpm status to anyone past Cloudflare Access, without a GUI login. `?full` shows in-flight request URIs. Add `path: ^/status` → `http_status:404` to the ingress example.
- **R9, concurrent `ensure` runs (Low).** Concurrent runs (boot rc.d plus cron, or install) share one tmp name. One process can rename the file while another is truncating or writing it, which briefly exposes an empty `authgui.inc`. Fixed by the per-process name and lock in R3.
- **R10, case-variant lockout of distinct local users (Low, availability).** Local `Bob` and `bob` are different accounts. Once `bob` has a passkey, `Bob` gets the "registered spelling" page from outside trusted networks, even with Enforce off. A low-privileged `bob` with access to `system_webauthn.php` can do this to `Bob`. Consider applying the variant rule only to sessions whose `authsource` is not "Local Database".
- **Trusted network set to a single IP inside a shared LAN.** The README suggests "your admin PC's address". Any host on the same L2 segment can take that address over when the PC is off. Recommend a separate management VLAN.
- **RP ID change.** Sessions verified before an RP ID change stay verified. The credential's `rp_id` is not checked in `verified`.
- **Notice and e-mail flooding.** Someone with the password can open sessions in a loop and trigger a notice and e-mail every 5 failures.
- **`webauthn_hmac_key()` first-run race.** A reader that sees the half-written key file can replace the key. This only affects availability.

## Checked and found sound

- **Entry points.** Every PHP file under `usr/local/www` reaches `authgui.inc`, through `guiconfig.inc`, `status_output.inc` or `status_logs_common.inc`, or reaches `auth_check.inc`. The exceptions are `csrf_error.php`, class files and `includes/functions.inc.php`, which output nothing, plus `xmlrpc.php` (guarded).
- **Hook placement.** The authgui hook sits after `session_auth()` and before `getAllowedPages()`/`isAllowedPage()`. The `postafterlogin` path still reaches the gate.
- **Gate behaviour.** POSTs to a gated page never execute: the gate exits and redirects with a GET. csrf-magic is loaded before `authgui.inc`, so gate POSTs carry tokens.
- **`auth_check.inc` hook.** It runs after `page-match` is read. It nulls `page-match` unless the current request would be `verified` or `skip`, then falls through to `authgui.inc` and the gate (AJAX gets 401). Trusted-network sessions moved to the tunnel lose their cached privileges.
- **Session handling.** Exact-username `verified` state, `session_regenerate_id(true)` after an assertion, and the per-session failure limit all work. A re-login under a different name loses `verified`.
- **Challenges.** HMAC over purpose, session ID, exact username, nonce and expiry. The fields are unambiguous: fixed-length payload last, purpose and SID free of NUL. The nonce is consumed before signature verification, so it cannot be retried. The expiry is inside the MAC. An unreadable key or used-nonce file fails closed.
- **WebAuthn §7.1/§7.2.** Checked: `type`, the challenge (re-encoded and compared in constant time), exact origin match, `crossOrigin` refused, RP ID hash, UP always and UV when required, and the signature over `authData ‖ SHA-256(clientDataJSON)` with the stored algorithm. Also: the counter (strictly increasing when non-zero), credential ID length ≤ 1023, duplicate IDs refused across users, and the algorithm bound to the COSE `kty`/`crv`.
- **COSE→PEM.** Correct SPKI encoding for P-256 (point checked by OpenSSL), Ed25519 and RSA ≥ 2048 bits.
- **CBOR (RFC 8949).** Indefinite lengths and floats are refused, 64-bit arguments are range-checked, duplicate and text-vs-integer keys are handled, depth is limited, and trailing bytes are refused. 30,000 mutated attestation objects raised only the expected exceptions.
- **Proxy and trusted-network logic.** CF-Connecting-IP is believed only from configured cloudflared peers. Proxy headers or a cloudflared peer never qualify as a trusted network. IPv4-mapped and scoped addresses fail closed. A `/0` network is refused. Trusted networks require a cloudflared source. The XMLRPC guard runs before any XMLRPC code.
- **Output and logging.**
  - XSS: escaped everywhere, including notices (pfSense `htmlentities` plus `htmlspecialchars`) and config-history descriptions.
  - Redirects: no open redirect (`webauthn_safe_redirect`).
  - Logs: control characters stripped. `LOG_USER` lines go to `system.log`, while sshguard reads only `auth.log` (syslog.inc 268, 539).
- **Backups.** `*.webauthn.orig` and the tmp file in the web root are refused by nginx's `\.orig$` rule. The old `.webauthn-orig` backups are migrated.
- **Hook upgrades.** Old hook versions are fully replaced, and v1's `file_exists()` fail-open guard is removed by `ensure`.
- **Missing files.** If the package files are missing, the hooks fail closed.
