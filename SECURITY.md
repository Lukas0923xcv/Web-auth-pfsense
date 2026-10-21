# Security

This package controls who gets admin access to a firewall. Please read this before trusting it.

## Review status

**No human has audited this code yet.** It was written with an AI assistant and went through several AI-driven review rounds; the latest one is recorded below. The test suite covers every finding and runs on every push. That catches regressions, but it does not replace a review by someone who knows WebAuthn and pfSense.

If you review it, start with [docs/REVIEW-GUIDE.md](docs/REVIEW-GUIDE.md), and please open an issue with what you looked at and what you found, even if you found nothing. Human reviews will be linked here.

| Date | Reviewer | Scope | Result |
|---|---|---|---|
| 2026-10-21 | AI adversarial review (separate agent, no access to the authoring context) | gate, webauthn, challenge, storage, xmlrpc_guard | 2 medium, 2 low, 2 info; all fixed, see below |
| 2026-10-21 | AI scoring review, round 1 (separate agent) | whole repository against the improvement rubric | 2 low, 2 info; fixed in 1.3.0, see the second table below |
| — | *human review wanted* | | |

## Reporting a vulnerability

Please do **not** open a public issue for a vulnerability. Use GitHub's private reporting: **Security > Report a vulnerability** on the repository page. Include the pfSense version, the package version (`/usr/local/pkg/webauthn/hook.php status`) and the steps to reproduce.

Until a fix is out, you can switch the second factor off under **System > WebAuthn Passkeys > Settings**, or remove the package (see the README).

## What it is meant to protect against

- **A stolen or guessed GUI password**, used through the Cloudflare Tunnel or from any network that is not marked trusted: without a registered passkey, the session never gets past the passkey page.
- **Replayed or forged passkey responses**: each challenge is signed with a key only the firewall knows, tied to the session, user and purpose, expires after 5 minutes, and can be used only once.
- **Cloned authenticators**, as far as their signature counter reveals them.
- **Tunnel traffic posing as local traffic**: requests from the cloudflared address, carrying proxy headers, or coming from the firewall's own addresses never get the trusted-network exemption.
- **Password-only XMLRPC** (HA sync, which can run commands as root): refused through a proxy, and while the second factor is on, from everyone except configured peers and trusted networks.
- **Many passkey attempts** (guessing a passkey is not possible, so this is defence in depth): 5 failures end a session; 10 from one address (IPv6: one /64) for one account, over any number of sessions, lock that address out of the account's passkey step for 15 minutes; after 30 failures for an account from any addresses, it takes at most one attempt every 20 seconds.
- **Answers made for another account**: a passkey of another account is refused, and so is a user handle that is not this account's (WebAuthn §7.2 steps 5 and 6).

## What it does not protect against

- Anyone on a **trusted network** who has the password. Keep trusted networks narrow.
- **SSH, the console, VPN** and other services, and packages with their own login.
- An attacker who can already **run code on the firewall** or change its files.
- A **future pfSense version** that changes the code a hook attaches to. The hook is then not applied and a GUI notice says so (CI checks the hooks weekly against pfSense's development branch to see this coming).
- The **upgrade window** below.

## The upgrade window, exactly

A pfSense upgrade replaces `/etc/inc/authgui.inc`, `/etc/inc/auth_check.inc` and `/usr/local/www/xmlrpc.php` while the system runs, and then reboots. The package puts its hooks back in two ways:

- **cron, every minute** (`hook.php ensure`), while the system runs;
- **at boot**, as an early shell command. pfSense's `rc.bootup` runs early shell commands (`system_do_shell_commands(1)`) before it starts the web server (`system_webgui_start()`), so the GUI never accepts a login after a boot without the hooks in place. The package's rc.d script is a second, later safety net.

The window in which the GUI accepts a password without a passkey therefore opens when the upgrade writes a replaced file, and closes at the next cron minute (at most 60 seconds later) or at the reboot, whichever comes first. A config restore does not open it (it does not touch those files). If the new pfSense version changed the code a hook attaches to, the window stays open until a fixed package version is installed; the notice and `hook.php status` say so.

## Accepted risks

Every risk below needs the account's password. Changing the password ends it.

- **Someone with the password, at the same client address as the real user** (for example behind the same NAT), can lock that address out of the account's passkey step for 15 minutes by failing on purpose. Without a lock, there would be no limit on attempts. The user can still sign in from another address or a trusted network.
- **Someone with the password and many addresses** is not locked out, only throttled: after 30 failures they get one attempt every 20 seconds, at most 4,320 a day, each against a passkey signature that cannot be guessed. A hard account-wide lock would instead let them lock out the real user from anywhere. While they keep this up, the real user may also have to wait up to 20 seconds per attempt.
- **The first passkey of an account can be registered with the password alone** when Enforce is off (or from a trusted network): the password already gives full access there, so asking for a passkey to add the first one would protect nothing. Once an account has a passkey, adding another needs a session verified with one. Turn Enforce on once every account has its passkey.
- **A damaged file in /conf** (attempt counts, counters, revocation list) stops passkey sign-ins until it is removed: the package fails closed rather than guess. The log names the file; [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) says what to do.

## Findings of the 2026-10-21 review, and what was done

| ID | Severity | Finding | Resolution |
|---|---|---|---|
| F1 | Medium | The account-wide failed-attempt lock (then new, unreleased) let anyone with the password keep the real user locked out from anywhere. | Fixed in 1.2.0: the limit is per account **and client address**; the account-wide total only raises a notice. Test: `tests/failure_limit_test.php` ("the right passkey works from another address while the attacker's is locked"). |
| F2 | Medium | Cloudflare private-network (WARP) traffic forwarded by cloudflared on the firewall arrives from the firewall's own LAN address without proxy headers, and got the trusted-network exemption and XMLRPC access. | Fixed in 1.2.0: loopback and the firewall's own addresses are never a trusted network, and reach XMLRPC only if listed as peers. Tests: `tests/xmlrpc_enrolment_replay_test.php` (F2). |
| F3 | Low | Registering a removed credential ID under another account lifted the revocation, so a later config restore could bring the removed record back. | Fixed in 1.2.0: revocation is by ID and key and is never lifted. Test: `tests/concurrency_and_config_test.php` (F3). |
| F4 | Low | A forged login POST with an empty username stripped a session's passkey verification. | Fixed in 1.2.0: a sign-in needs a non-empty username, as in pfSense's `session_auth()`. Test: `tests/xmlrpc_enrolment_replay_test.php` (F4). |
| F5 | Info | Log lines could carry unfiltered client text (bidi overrides, line separators, unlimited length). | Fixed in 1.2.0: log text goes through `webauthn_plain()`. Test: (F5). |
| F6 | Info | The cloudflared source had no size limit, so `0.0.0.0/0` would make forged client addresses appear in logs. | Fixed in 1.2.0: same /8 and /16 limit as trusted networks. Test: (F6). |

## Findings of the round-1 scoring review, and what was done

| ID | Severity | Finding | Resolution |
|---|---|---|---|
| L1 | Low | With the attempt limit per account and address, changing addresses gave unlimited attempts. | Fixed in 1.3.0: account-wide throttle (one attempt per 20 s after 30 failures), and IPv6 counted per /64. Test: `tests/failure_limit_test.php` ("a new address is throttled too", "same IPv6 /64"). |
| L2 | Low | `response.userHandle` (§7.2 step 6) and `topOrigin` were not checked. | Fixed in 1.3.0: a user handle that is not the account's is refused, and any `topOrigin` is refused as cross-origin. Tests: `tests/webauthn_vectors_test.php` (step 6, topOrigin), `tests/gate_flow_test.php`. |
| I1 | Info | `webauthn_xmlrpc_guard()` itself (403, exit) had no test. | Tested end to end in 1.3.0: `tests/xmlrpc_enrolment_replay_test.php` ("guard: ..."). |
| I2 | Info | The first passkey can be enrolled with a password alone while Enforce is off. | By design; now listed under Accepted risks. |
