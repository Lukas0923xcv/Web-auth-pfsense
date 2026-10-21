# Tests

Run everything with:

```sh
sh tests/run_all.sh              # as root it also runs the tests that change the system
COVERAGE=1 sh tests/run_all.sh   # also measures line coverage (needs the pcov extension)
```

You need PHP 8.2+ with the openssl, sodium, intl and mbstring extensions. The tests run off the firewall: `tests/support/` stubs the few pfSense functions the package calls. Each suite gets its own empty temp directory. GitHub Actions runs the whole set on PHP 8.2, 8.3 and 8.4 for every push.

| Suite | What it covers |
|---|---|
| `core_test.php` | Registration and sign-in verification for ES256, RS256 and EdDSA; CBOR and authenticator data parsing; settings validation; access-path decisions; challenges; hook patching. |
| `webauthn_vectors_test.php` | Real authenticator responses from other WebAuthn libraries (see `fixtures/vectors/README.md`), and one negative test per verification step of WebAuthn §7.1 and §7.2, including topOrigin and userHandle. |
| `gate_flow_test.php` | End to end through `webauthn_gate()`: challenge page, sign-in, replay, sessions, LAN hostname under a parent RP ID, another user's passkey or user handle. |
| `gate_session_test.php` | End to end: a verification is bound to its login, age, RP ID and user-verification setting. |
| `gate_ldap_and_revocation_test.php` | End to end: an LDAP spelling of a username cannot pass the gate; removing a passkey signs out its sessions. |
| `failure_limit_test.php` | The failed-passkey limits per account and address (IPv6: /64) and the account-wide throttle: new sessions or new addresses cannot reset them, the real user elsewhere is not locked out, and a damaged or unwritable attempt list stops passkey sign-ins (fail closed). |
| `hooks_and_policy_test.php` | Hooks fail closed and replace older ones; cached page privileges; username variants; trusted-network rules; CBOR key confusion; revocation. |
| `storage_and_sessions_test.php` | Signature counters, verified-session state, lost updates, LDAP/RADIUS spellings, local identities, notice text, passkey names, deleted accounts, hardening limits. |
| `concurrency_and_config_test.php` | Parallel removals (real parallel processes), LDAP names, per-account challenge limit, revocation under the config lock, changes made outside the package. |
| `xmlrpc_enrolment_replay_test.php` | LDAP/RADIUS spellings, who may enrol a passkey, XMLRPC refusal (also end to end through `webauthn_xmlrpc_guard()`), challenge replay, the firewall's own addresses, log line cleaning. |
| `config_reload_fallback_test.php` | Config reload on pfSense versions without `config_read_file()` (2.7.x); a failed reload changes nothing. |
| `fuzz_parsers_test.php` | 20,000 mutated CBOR, authenticator data and COSE inputs: only the package's own exceptions, never a PHP warning. |
| `full_disk_hook_test.sh` | Root only. On a full disk, patching `authgui.inc` fails and leaves the file unchanged. |
| `install_uninstall_test.sh` | Root only, and only where `WEBAUTHN_SYSTEM_TEST=1` (CI): runs the real `install.sh` and `uninstall.sh` against pfSense's files and checks they come back byte-identical. CI runs it on `fixtures/` and on the files pfSense CE 2.8.1 ships. With `WEBAUTHN_SYSTEM_TEST=1`, a skip counts as a failure. |

`fixtures/` holds copies of pfSense's `authgui.inc`, `auth_check.inc` and `xmlrpc.php` from github.com/pfsense/pfsense master (Apache 2.0). The 2.8.1 release has no tag there, so CI takes the 2.8.1 copies from the release's own package (`tools/upstream_anchors.sh release`). `support/` holds the stubs and helpers: a CBOR encoder, a software authenticator, the one-request gate runner and the coverage collector.
