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
| `webauthn_vectors_test.php` | Real authenticator responses from other WebAuthn libraries (see `fixtures/vectors/README.md`), and one negative test per verification step of WebAuthn §7.1 and §7.2. |
| `gate_flow_test.php` | End to end through `webauthn_gate()`: challenge page, sign-in, replay, sessions, LAN hostname under a parent RP ID. |
| `gate_session_test.php` | End to end: a verification is bound to its login, age, RP ID and user-verification setting. |
| `gate_ldap_and_revocation_test.php` | End to end: an LDAP spelling of a username cannot pass the gate; removing a passkey signs out its sessions. |
| `failure_limit_test.php` | The per-user failed-passkey limit: new sessions cannot reset it, and a damaged or unwritable counter file locks the passkey step (fail closed). |
| `hooks_and_policy_test.php` | Hooks fail closed and replace older ones; cached page privileges; username variants; trusted-network rules; CBOR key confusion; revocation. |
| `storage_and_sessions_test.php` | Signature counters, verified-session state, lost updates, LDAP/RADIUS spellings, local identities, notice text, passkey names, deleted accounts, hardening limits. |
| `concurrency_and_config_test.php` | Parallel removals (real parallel processes), LDAP names, per-account challenge limit, revocation under the config lock, changes made outside the package. |
| `xmlrpc_enrolment_replay_test.php` | LDAP/RADIUS spellings, who may enrol a passkey, XMLRPC refusal, challenge replay. |
| `config_reload_fallback_test.php` | Config reload on pfSense versions without `config_read_file()` (2.7.x); a failed reload changes nothing. |
| `fuzz_parsers_test.php` | 20,000 mutated CBOR, authenticator data and COSE inputs: only the package's own exceptions, never a PHP warning. |
| `full_disk_hook_test.sh` | Root only. On a full disk, patching `authgui.inc` fails and leaves the file unchanged. |
| `install_uninstall_test.sh` | Root only, and only where `WEBAUTHN_SYSTEM_TEST=1` (CI): runs the real `install.sh` and `uninstall.sh` against pfSense fixture files and checks they come back byte-identical. |

`fixtures/` holds copies of pfSense CE's `authgui.inc`, `auth_check.inc` and `xmlrpc.php` (Apache 2.0, from github.com/pfsense/pfsense). `support/` holds the stubs and helpers: a CBOR encoder, a software authenticator, the one-request gate runner and the coverage collector.
