# Changelog

All notable changes. Versions follow [semantic versioning](https://semver.org/); what users must do after an update is in [docs/UPGRADE.md](docs/UPGRADE.md).

## [1.3.0] - 2026-10-21

### Security

- Account-wide throttle on failed passkey attempts: after 30 from any addresses in 15 minutes, one attempt per 20 seconds. IPv6 addresses count per /64 for the per-address lock (round-1 review L1).
- `response.userHandle`, when sent, must be the account's user handle (WebAuthn §7.2 step 6), and a `topOrigin` in the client data is refused as cross-origin (L2).
- SECURITY.md lists the accepted risks of the attempt limits and of enrolling the first passkey with a password alone (I2).

### Development

- End-to-end tests of `webauthn_xmlrpc_guard()` (I1), of signing in with another user's passkey or user handle, of the throttle and of IPv6 /64 grouping.
- CI runs the install/uninstall test on the files pfSense CE 2.8.1 ships, and a requested system test that cannot run now fails.

## [1.2.0] - 2026-10-21

### Security

- Failed passkey attempts are counted per account and client address in `/conf/webauthn_failures.json`, before each attempt is verified. Ten from one address, over any number of sessions, lock that address out of the account's passkey step for 15 minutes; other addresses are not affected. If the count cannot be stored or the file is damaged, no passkey is verified (fail closed).
- Requests from the firewall's own addresses (loopback, interface addresses) never get the trusted-network exemption, and use XMLRPC only if listed as peers. Cloudflare private-network (WARP) routes through cloudflared on the firewall arrive that way without proxy headers (review finding F2).
- Removed passkeys are revoked by credential ID and key, and nothing lifts a revocation. Registering a removed ID under another account could otherwise bring the removed record back through a config restore (F3).
- A POST with an empty username no longer counts as a sign-in, so a cross-site request cannot strip a session's passkey verification (F4).
- Log lines are plain single-line text of bounded length (F5). The cloudflared source has the same /8 and /16 size limit as trusted networks (F6).
- Authenticator data with the backup-state flag but without backup eligibility is refused (WebAuthn Level 3). A stored key must match its algorithm (EC P-256 for ES256, RSA of at least 2048 bits for RS256, Ed25519 for EdDSA).

### Changed

- `webauthn_gate()` is split into smaller functions; the "Remove" button is greyed out for a user's last usable passkey.
- Uninstall removes the `*.webauthn.orig` backups once the originals are back.
- Removed dead code: `webauthn_ldap_account()` and `webauthn_ldap_nostrip()`.

### Development

- Real authenticator responses from py_webauthn's test suite (ES256, RS256, EdDSA; registration and sign-in), and one negative test per verification step of WebAuthn §7.1 and §7.2.
- CI: line coverage (at least 85% for the core files) in the job summary, shellcheck, PHPStan level 6, an end-to-end install/uninstall test, a check of the README pin, the hooks against pfSense CE 2.8.1's files (fails on a break) and pfSense master (warns on drift), and a tag-triggered release workflow with SHA256SUMS and build provenance.
- Test suites have descriptive names; docs moved to `docs/`.

## [1.1.0] - 2026-10-21

### Changed

- The hooks are re-applied every minute instead of every 5 minutes.
- `install.sh` refuses to run without root or outside pfSense and checks the download before changing anything.
- The README install command is pinned to a commit and checks its sha256.
- `webauthn.inc` was split into `webauthn.inc`, `storage.inc` and `challenge.inc`.
- Added `SECURITY.md`, `LICENSE` and a CI workflow.

## [1.0.0] - 2026-10-21

First version with a visible version number.
