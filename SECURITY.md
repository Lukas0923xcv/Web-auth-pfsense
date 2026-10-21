# Security

This package controls who gets admin access to a firewall. Please read this before trusting it.

## Review status

**No human has audited this code yet.** It was written with an AI assistant and went through several AI-driven review rounds. The test suite (`tests/`) covers what those reviews found, and it runs on every push. That catches regressions, but it does not replace a review by someone who knows WebAuthn and pfSense.

If you review it, please open an issue with what you looked at and what you found, even if you found nothing. A record of independent reviews is the most useful thing this project can get.

## Reporting a vulnerability

Please do **not** open a public issue for a vulnerability. Use GitHub's private reporting instead: **Security > Report a vulnerability** on the repository page. Include the pfSense version, the package version (`/usr/local/pkg/webauthn/hook.php status`) and the steps to reproduce.

Until a fix is out, you can switch the second factor off under **System > WebAuthn Passkeys > Settings**, or remove the package (see the README).

## What it is meant to protect against

- **A stolen or guessed GUI password**, used through the Cloudflare Tunnel or from any network that is not marked trusted: without a registered passkey, the session never gets past the passkey page.
- **Replayed or forged passkey responses**: each challenge is signed with a key only the firewall knows, tied to the session, user and purpose, expires after 5 minutes, and can be used only once.
- **Cloned authenticators**, as far as their signature counter reveals them.
- **Tunnel traffic posing as local traffic**: requests from the cloudflared address, or carrying proxy headers, never get the trusted-network exemption.
- **Password-only XMLRPC** (HA sync, which can run commands as root): refused through a proxy, and while the second factor is on, from everyone except configured peers and trusted networks.

## What it does not protect against

- Anyone on a **trusted network** who has the password. Keep trusted networks narrow.
- **SSH, the console, VPN** and other services, and packages with their own login.
- An attacker who can already **run code on the firewall** or change its files.
- The time between a **pfSense upgrade** and the next cron run (up to one minute), when pfSense has replaced the patched files and the hook is missing.
- A **future pfSense version** that changes the code the hook attaches to. The hook is then not applied, and a GUI notice says so.

## Where to look when reviewing

In order of how much depends on them:

1. `src/usr/local/pkg/webauthn/webauthn_lib.inc` and `cbor.inc`: verification of registrations and sign-ins (WebAuthn §7.1 and §7.2), the COSE key conversion and the CBOR parser.
2. `src/usr/local/pkg/webauthn/gate.inc`: the gate that runs after every password check, and the `auth_check.inc` hook.
3. `src/usr/local/pkg/webauthn/webauthn.inc`: `webauthn_session_status()`, `webauthn_request_source()` and the trusted-network rule; username handling for LDAP/RADIUS.
4. `src/usr/local/pkg/webauthn/challenge.inc`: challenge format, single use, limits.
5. `src/usr/local/pkg/webauthn/storage.inc`: credential storage, revocation, counters, locking.
6. `src/usr/local/pkg/webauthn/hook.inc` and `hook.php`: how pfSense files are patched and kept patched.
7. `install.sh`: runs as root.

Run the tests with `sh tests/run_all.sh` (PHP 8.2+ with openssl, sodium, intl and mbstring; as root it also runs the full-disk test).
