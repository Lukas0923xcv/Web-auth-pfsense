# Fourth security review: pfSense WebAuthn second factor

Base: `b7481ae`. Source of the findings: a full security audit (profile standard). Only finding 1 was confirmed in that audit; findings 2–8 depended on pfSense code outside this repository. All are fixed defensively in the add-on, so they hold whatever pfSense does.

pfSense behaviour was checked against `pfsense/pfsense` master (no public 2.8.1 tag). The fixtures in `tests/fixtures/` match master byte for byte. The pfSense facts the fixes rely on:

| Question | Answer (pfSense source) | Used for |
|---|---|---|
| Does a password sign-in clear `$_SESSION`? | No. `session_auth()` (`auth.inc`) only calls `session_regenerate_id()` and sets its own keys. | 2: bind the verification to the session ID; clear it on a login POST |
| Field names of the login form | `login`, `usernamefld` (`authgui.inc`) | 2 |
| Does `write_config()` write the whole in-memory config? | Yes (`config_write_file()`); success returns the config array, failure `false`/`-1` | 3 |
| How to reload config.xml | Current pfSense: `config_read_file(false, false)` (`config.lib.inc`, no cache). pfSense 2.7.2 (`RELENG_2_7_2`) does not have it; its `parse_config(true)` can `die()` or restore a backup. Whether 2.8.1 has `config_read_file()` could not be checked (no public 2.8 branch or tag), so the add-on uses it when present and otherwise parses config.xml with pfSense's `parse_xml_config()` into the global `$config` both versions use; if neither works the change is refused | 3 |
| Lock taken by `write_config()` | `lock('config')`, i.e. `/tmp/config.lock`; the add-on's lock is `/conf/webauthn_config.lock`: no deadlock | 3 |
| How `getUserEntry()` resolves names | array index `$userindex[$name]` built when `auth.inc` loads; PHP makes only canonical decimal strings integer keys, so it is an exact string match. `'1e3'` never finds `'1000'`. Including `auth.inc` from a function would leave `$userindex` local, so the add-on repeats the exact lookup over `system/user` itself | 5, 8 |
| Local account uid | `system/user/*/uid` | 8 |
| Are notices escaped? | Yes: `file_notice()` applies `htmlentities()`, `head.inc` `htmlspecialchars()` | 6: plain text only, no extra escaping |
| Does the XML writer filter control characters? | No: `htmlentities(…, ENT_SUBSTITUTE \| ENT_XML1)` replaces invalid UTF-8 but keeps `\x0b` etc., which makes config.xml invalid XML 1.0 | 7 (confirmed, not only a hint) |
| `system/authserver` entries | `type` is `ldap` or `radius` | 4: Settings warning |

Tests: `tests/review4/review4_test.php` (113 checks), `tests/review4/gate_review4.php` (14 checks, through the real `webauthn_gate()`) and `tests/review4/reload_fallback.php` (4 checks, pfSense without `config_read_file()`). All earlier suites pass unchanged in substance; their stubs now return the config from `write_config()` as pfSense does, use temp paths for the new state files, and build verification states with the new fields.

## Status

| Finding | Fix | Test |
|---|---|---|
| 1 Signature counter not atomic (confirmed, low) | `webauthn_advance_sign_count()` compares and stores under the counter lock; the gate refuses the assertion if the counter did not increase or could not be stored. Registration stores the counter before the passkey is saved and aborts if it cannot. Removing a passkey removes its counter. | review4 §1; gate_review4 "counter 50 then 10", "counter cannot be stored" |
| 2 Verified state not bound to the password login | The verification records session ID, time, RP ID and UV. It is valid only for the same session ID (pfSense renews it at every password sign-in), for at most `WEBAUTHN_VERIFIED_MAX_AGE` (12 h), for the current RP ID, and with UV if UV is now required. A login POST clears it in the gate, and `auth_check.inc`'s fast path is refused for a login POST. `webauthn_verify_assertion()` returns the flags through an optional `$info` parameter; its result and arguments are unchanged. | review4 §2; gate_review4 "login POST into a verified session", "another session ID" |
| 3 Lost update in config.xml | `webauthn_config_update()`: own lock, reload from disk, change, `write_config()`, success only if it returns the config. Used for adding and removing passkeys and for saving settings. Removal deletes every record with the ID, re-reads the config to confirm, and reports failure otherwise. | review4 §3 (stale snapshot, stale write, duplicate records) |
| 4 LDAP/RADIUS spellings | Katakana folded to hiragana (`mb_convert_kana 'c'`), `%` as a realm separator. Without intl/mbstring every passkey counts for every remote user (logged once). Settings tab warns while LDAP/RADIUS servers exist and Enforce is off. README states it more strongly. | review4 §4 |
| 5 Local identity only by the typed name | `webauthn_session_identity()`: local sessions use the account name from the user database, '' (refused) if none matches; used by the gate, `auth_check.inc` (through the session status) and the settings page. | review4 §5; gate_review4 "unresolvable local name" |
| 6 Names unfiltered in notices / history | `webauthn_plain()` (no Cc/Cf/Zl/Zp, valid UTF-8, length limit) applied to every notice and every config-history description; user and passkey names quoted. | review4 §6 |
| 7 Arbitrary bytes in passkey names | `webauthn_valid_passkey_name()`: `^[\p{L}\p{N} ._()\-]{1,64}$`, valid UTF-8. Existing names are displayed as before (escaped). | review4 §7 |
| 8 Passkeys bound to the name only; restore | Local registrations store the uid; a passkey whose uid no longer matches the account (or whose account is gone) is ignored and marked "belongs to a deleted account". Removed IDs go to `/conf/webauthn_revoked.json` and are never accepted again; registering the same ID again lifts that. | review4 §8 |
| 9 Session rotation on registration | `session_regenerate_id(true)` before the verification is recorded. | review4 §9 (source order) |
| 9 Registration while disabled | With the second factor off, a further passkey for an account that has one needs an admin. | review4 §9 |
| 9 Last passkey from a skip session | Users other than admins need a verified session to remove their last passkey; admins keep the recovery path. | review4 §9 |
| 9 Large networks | Trusted networks and XMLRPC peers must be at least /8 (IPv4) or /16 (IPv6). | review4 §9 |
| 9 Lockout by RP ID change | Saving an RP ID none of the admin's passkeys has is refused outside trusted networks (`webauthn_settings_lockout_error()`). | review4 §9 |
| 9 `$logincss` | Must be six hex digits. | gate_review4 "login colour" |
| 9 Notice flood | Failed-attempt notices at most once per user per 15 minutes (`/conf/webauthn_notices.json`). | review4 §9 |
| 9 Nonce list bound | At most 10 000 unexpired entries, then refused. | review4 §9 |
| 9 Clock | One `$now` per check; a challenge expiring later than a fresh one could is refused. | review4 §9 |
| 9 Temp files | `webauthn_write_json()`: per-process name, `fopen('x')`, mode 0600, rename. | review4 §9 |
| 9 Install line | README installs `<commit-sha>`, with instructions. | — |

## Found during the recheck of these fixes

| Finding | Fix | Test |
|---|---|---|
| R4-A The nonce cap from item 9 is a lever for denial of service: challenges were recorded as used before the signature was checked, so someone with only the password could submit about 33 forged responses per second and fill the list, refusing every passkey login for 5 minutes. | `webauthn_use_challenge()` checks and records under one lock and records the challenge only after the whole verification (signature, counter) succeeded. Only completed ceremonies fill the list; one signed response is still accepted only once, also in parallel. Used for the login and the registration. If the use cannot be recorded, the verification fails. | review4 §9 "failed verifications do not use up challenges", "only once", "cannot be recorded" |
| R4-B Clearing the failure count on a login POST (as item 2 suggested) would let a password holder reset it every four attempts and never raise the "5 failed attempts" notice. | Only the verification is cleared; the failure count stays. | gate_review4 "a login POST keeps the failure count" |
| R4-C A damaged revocation list would let passkeys that were removed and brought back by a restore count again. | A damaged list fails closed: every passkey still counts as present (no skipping), none is accepted, and no passkey can be added or removed until the file is repaired or removed; logged once. | review4 §8 "damaged revocation list" |
| R4-D On pfSense without `config_read_file()` the reload of item 3 would silently not happen. | Fallback to `parse_xml_config()` on config.xml; refuse the change if that fails too. | reload_fallback.php |
| R4-E A config with a single local user stored as a bare element (not a list) would resolve no local account, refusing every local sign-in (fail closed, but wrong). | `webauthn_local_user()` wraps a bare element, as the credential list already did. | review4 §5 "lone user element" |
| R4-G Registering a revoked credential ID lifted the revocation before the config was saved, without checking the result. If the save failed (for example for a user with pfSense's "Deny Config Write" privilege), an old record of that ID brought back by a restore became valid again; with attestation "none" anyone may choose the ID. | The revocation is lifted only after `write_config()` succeeded; a failure there is reported. | review4 §8 "re-registering a revoked ID" (fails against the previous code) |
| R4-H A damaged signature counter file was read as empty: the next sign-in was accepted and stored a file with only its own counter, wiping all others and so the clone detection. | A damaged counter file (like the revocation list) refuses sign-ins and registrations and is left untouched until repaired or removed; logged once. An unreadable used-challenge list is treated as damaged too. | review4 §1 "damaged counter file" |
| R4-F The revocation list is not in config backups: restoring a backup taken before a removal onto a reinstalled firewall brings that passkey back. An old backup is the old state, so code cannot prevent it. | README says to remove such passkeys again after a restore onto a reinstalled system. | — |

## Independent review of the state at ca954e9

A separate reviewer, without the author's reasoning, audited all files again against threat models a–d. Its reproductions were re-run here before fixing. Tests: `tests/review4/review4b_test.php` (21 checks, including two processes racing).

| Finding | Fix | Test |
|---|---|---|
| R4-I (confirmed, medium) Two parallel removals by a non-admin with a password-only session each saw the other passkey as "the one left" and removed both; the account then counted as passkey-free, so the password alone could enrol a new passkey. Reproduced 20/20. | `webauthn_delete_credential()` decides "another usable passkey is left" under the config lock on the reloaded config, together with revoking and removing. Only passkeys for the current RP ID count as usable. | review4b R4-I (fails without the locked check) |
| R4-J (confirmed, low) LDAP user x could sign in as `x\carol` (pfSense authenticates the part before `\`), register a "first" passkey under that name, and thereby make carol's account look as if it had a passkey: carol was refused through the tunnel and could not enrol. | `webauthn_registrable_name()`: through LDAP, passkeys can only be stored under names pfSense authenticates as that same account (honouring `ldap_nostrip_at`); names with control or format characters are refused for every backend. | review4b R4-J |
| R4-K (confirmed, low) The global cap of the used-challenge list could be filled by anyone holding one passkey (repeated registrations, also of an existing ID, which saved nothing but used a challenge), blocking every passkey sign-in. | Per-account limit of 50 live challenges (the global cap stays); registration verifies and saves inside the challenge check, so a ceremony that saves nothing uses nothing; at most 20 passkeys per account. | review4b R4-K |
| R4-L (theoretical) Re-registering a revoked ID while an admin removed it again could end with the record gone and the ID unrevoked. | Lifting a revocation runs in the after-save step inside the config lock; removal revokes inside the same lock. | review4b R4-L |
| R4-M (theoretical) Another pfSense page saving an older copy of the whole config at the same moment can undo a passkey registration or settings change, for example switch the second factor off, silently. | Cannot be prevented from the add-on (pfSense pages do not take its lock). Made visible: the package records a hash of its config section after each own save; the first GUI request that sees a different section raises a notice. The check runs before the enable check, so a switch-off is reported too. | review4b R4-M |
| R4-N (theoretical) Control characters in remote login names reach config.xml through passkey records. | Covered by R4-J (refused). pfSense itself writes the same name into revision entries on any save by that session; outside the add-on. | review4b R4-J |

Kept as documented limits (README): unprotected windows while a pfSense upgrade or a removed boot command and cron job leave a hook missing (the hook cannot run when it is not there; a notice is raised when patching fails); name equivalences of LDAP/RADIUS servers beyond the folding rules, for which Enforce is the answer.

## Complete recheck after all fixes

Every file was re-read in its final state. `xmlrpc_guard.inc`, `hook.inc`, `hook.php`, `cbor.inc`, `webauthn.js`, the rc.d script and the install scripts are byte-identical to the state verified in the third review; `webauthn_lib.inc` differs only by the optional `$info` parameter.

| Area | Checked | Result |
|---|---|---|
| Entry points | the gate runs after `session_auth()` before privileges; `auth_check.inc` gets cached privileges only for `verified`/`skip`, now also with local sessions in its lean context (only `config.inc` loaded) | sound (audit_test R4 checks) |
| Verification state | revoked before verified; bound to session ID, age, RP ID, UV; login POST clears it; new verification only after `session_regenerate_id(true)` (gate and registration) | sound |
| Identity | local: exact lookup in `system/user` (bare element handled), '' refused; remote: typed name plus folded spellings; no-intl fallback | sound |
| Ceremonies | challenge HMAC (purpose, session, exact user), expiry window both ways, recorded only after full success under one lock, list cap only reachable by completed ceremonies | sound |
| WebAuthn verification | unchanged verifier, 20 000-input fuzz clean; counter compared and stored atomically | sound |
| Storage | config changes under own lock on reloaded config (both pfSense variants), success checked, removal confirmed; revocation lifted only after a successful save; revocation list, counter file and used-challenge list fail closed when damaged or unreadable; all state files written whole, 0600, per-process temp | sound |
| Lock order | used-challenge → counter (login); config → counter → revoked (add); revoked, then config, then counter (remove): no cycle | sound |
| Lower-privileged user | own passkeys only; cannot revoke or reuse others' IDs (existence checked for the own name, duplicate IDs refused); last passkey needs a verified session | sound |
| Output | every page value escaped; notices and config history plain text; passkey names restricted | sound |
| Failure modes | missing/damaged state files, unwritable counter or list, unreadable config, missing intl/mbstring, missing `config_read_file()`, full disk (hook): all fail closed | sound |

No further finding.

## Residual behaviour (not a security risk)

- Passkeys registered before this version have no uid, so a local account deleted and recreated under the same name still counts them. That only fails closed: the new account then has to present a passkey it does not hold. Remove them (an admin can) and register new ones to bind them to the account.
