# Review guide

Thank you for reviewing this package. It adds a WebAuthn (passkey) step after the password login of the pfSense web GUI, by hooking into three pfSense files. It controls who gets admin access to a firewall, so an outside look is the most valuable thing it can get. **No human has reviewed it yet**: it was written with an AI assistant, and the reviews so far were AI reviews (their findings and fixes are listed in [SECURITY.md](../SECURITY.md)).

Please report what you looked at and what you found, even if you found nothing: open an issue titled "Review: <what you covered>". Report vulnerabilities privately instead (**Security > Report a vulnerability** on the repository page).

## Scope

In scope: everything under `src/`, plus `install.sh` and `uninstall.sh`, which run as root. Out of scope: pfSense itself, the browser, Cloudflare.

About 3,000 lines of PHP, no dependencies beyond PHP's openssl, sodium, intl and mbstring. Target: pfSense CE 2.8.1 (PHP 8.3).

## Threat model in one paragraph

An attacker knows a user's GUI password and reaches the GUI through a Cloudflare Tunnel or any network that is not marked trusted. They must not get a usable session without that user's passkey: not by replaying or forging a passkey response, using another spelling of the username (LDAP/RADIUS), riding a session that was exempt on a trusted network, spoofing proxy headers, racing parallel requests, using XMLRPC, or waiting for a config restore or a full disk. They must also not be able to lock the real user out from elsewhere. Anyone on a trusted network, and anyone who can run code on the firewall, is out of scope. The full list, including what is accepted, is in [SECURITY.md](../SECURITY.md).

## Files, in priority order

| # | File | What it does | Questions worth asking |
|---|---|---|---|
| 1 | `src/usr/local/pkg/webauthn/webauthn_lib.inc`, `cbor.inc` | Verifies registrations and sign-ins (WebAuthn §7.1, §7.2); COSE to PEM; the CBOR parser. | Is every step of §7.1/§7.2 that matters checked? Can a malformed CBOR or COSE structure confuse a check? |
| 2 | `src/usr/local/pkg/webauthn/gate.inc` | Runs after pfSense's password check on every GUI request (`webauthn_gate()`); also decides whether `auth_check.inc` may trust cached page privileges. | Is there any path through the gate that returns without a verified, exempt or disabled decision? |
| 3 | `src/usr/local/pkg/webauthn/webauthn.inc` | `webauthn_session_status()`, `webauthn_request_source()`, the trusted-network rule, LDAP/RADIUS username spellings, settings validation, logging. | Can a request look like trusted LAN traffic when it is not? Can a spelling of a name skip the passkey of another? |
| 4 | `src/usr/local/pkg/webauthn/challenge.inc` | Stateless HMAC challenges bound to session, user and purpose; single use under a lock. | Replay, cross-session or cross-purpose use, filling the used list. |
| 5 | `src/usr/local/pkg/webauthn/storage.inc` | Passkey records in config.xml, revocation by ID and key, signature counters, failed-attempt counts, locking and atomic writes. | Races between parallel requests; what a config restore or a stale save by another page can bring back. |
| 6 | `src/usr/local/pkg/webauthn/xmlrpc_guard.inc` | Refuses password-only XMLRPC except from peers and trusted networks. | Can XMLRPC (which can run code as root) be reached with a password alone? |
| 7 | `src/usr/local/pkg/webauthn/hook.inc`, `hook.php` | Patches the three pfSense files and keeps them patched (cron every minute, early boot). | Can a patch leave a file empty, truncated or without a hook while claiming success? |
| 8 | `src/usr/local/www/system_webauthn.php`, `webauthn/webauthn.js` | The settings and passkey page; the browser side of the ceremonies. | Who may register or remove passkeys, and from where? CSRF (pfSense's csrf-magic covers the forms), XSS. |
| 9 | `install.sh`, `uninstall.sh` | Run as root on the firewall. | Anything a download could do beyond installing the listed files. |

## Running the tests

On any Linux or macOS machine with PHP 8.2+ (openssl, sodium, intl, mbstring):

```sh
git clone https://github.com/Lukas0923xcv/web-auth-pfsense.git && cd web-auth-pfsense
sh tests/run_all.sh                 # all suites, lint, shellcheck if installed
COVERAGE=1 sh tests/run_all.sh      # also line coverage (needs pcov)
```

[tests/README.md](../tests/README.md) says what each suite covers. `tests/support/` has a software authenticator (`FakeAuthenticator`) and a one-request gate runner (`gate_step.php`) that make proofs of concept short: see `tests/gate_flow_test.php` for examples. CI also runs PHPStan (level 6) and checks the hooks against pfSense CE 2.8.1's own files.

To try it on a real firewall, follow [VM-TEST.md](VM-TEST.md) on a pfSense VM.
