# pfSense WebAuthn second factor

Adds a passkey / security-key (WebAuthn) step after the normal username and password login on the pfSense web GUI.

Target: pfSense CE 2.8.1. The hook anchors on the `session_auth()` block in `/etc/inc/authgui.inc`, which has kept the same shape for years. The installer refuses to patch, and says so, if that block is missing.

## How it works

1. The password login is unchanged (`session_auth()`).
2. Immediately after it, and before pfSense checks page privileges, `webauthn_gate()` runs on every GUI request. If the session has not yet passed WebAuthn, the gate shows a "Use passkey" page instead of the requested page.
3. The browser signs a single-use challenge: a random nonce with a 5-minute lifetime, HMAC-bound to the session, the user, and the purpose. Challenges are not stored in the session, so loading the page again does not invalidate one already in use. The server verifies the RP ID hash, the origin, the user-presence flag (and user verification if required), the signature, and the signature counter. On success it regenerates the session ID and lets the request through.

Supported algorithms: ES256, RS256, and Ed25519 (when PHP's sodium extension is present). These cover current platform passkeys (iCloud Keychain, Google Password Manager, Windows Hello) and hardware keys (YubiKey and others). Attestation is not requested (`attestation: "none"`).

Passkeys and settings live in `config.xml` under `installedpackages/webauthn`, so they are included in config backups. Signature counters are kept in `/conf/webauthn_signcount.json` so that a login does not create a new config revision.

## Install

From a pfSense shell (console option 8, SSH), or as one line joined with `&&` in **Diagnostics > Command Prompt**. Running the same command again updates an existing install and keeps settings and passkeys:

```sh
cd /root && fetch -o webauthn.tar.gz https://codeload.github.com/Lukas0923xcv/web-auth-pfsense/tar.gz/refs/heads/claude/vigilant-cray-p2utgq
rm -rf [Ww]eb-auth-pfsense-* && tar xzf webauthn.tar.gz && cd web-auth-pfsense-* && sh install.sh
```

The installer copies the files, lint-checks them, patches `/etc/inc/authgui.inc`, `/etc/inc/auth_check.inc` and `/usr/local/www/xmlrpc.php` (keeping copies with the suffix `.webauthn-orig`), and adds **System > WebAuthn Passkeys** to the menu. The second factor stays **disabled** until you turn it on.

- Check the hooks: `/usr/local/pkg/webauthn/hook.php status`. It prints one line per file: `present`, `OUTDATED` (re-run the installer) or `MISSING`.
- Uninstall: `sh uninstall.sh`. Passkeys and settings stay in `config.xml`.
- Upgrades: a pfSense upgrade replaces the patched files. `/usr/local/etc/rc.d/webauthn_hook.sh` re-applies the hooks at every boot, and pfSense upgrades reboot. Still, run `hook.php status` after upgrading. If pfSense ever changes the code a hook is anchored to, that hook is **not** applied, the installer exits with an error, and `webauthn: could not patch <file>` is logged.
- The hooks load the package files unconditionally. If the files are removed without running the uninstaller, the GUI stops working (fail closed) rather than skipping the passkey step.

## Access path: Cloudflare Tunnel + Cloudflare Access

Example layout: the GUI is published as `https://pfsense.example.com` through cloudflared, behind Cloudflare Access.

### Origin and RP ID come from the public hostname

TLS terminates at Cloudflare. cloudflared may reach pfSense over plain HTTP, or over HTTPS with an untrusted certificate. So the gate **never** uses `$_SERVER['HTTPS']`, the local scheme, or the port to decide anything. Instead:

- **RP ID** (setting): `pfsense.example.com`, or the parent domain `example.com` (see [Local fallback](#local-fallback)).
- **Allowed origins** (setting): defaults to `https://<RP ID>`. Set it to `https://pfsense.example.com`, plus any LAN hostname.

The browser reports the origin it actually used in `clientDataJSON`, and that origin is checked against this list. A request that reaches pfSense as plain HTTP from the tunnel is accepted, as long as the browser was on an allowed `https://` origin.

Settings validation rejects origins that are not `https://`, origins whose host is not the RP ID or a subdomain of it, and IP addresses as the RP ID.

### Client IP and GUI lockout

pfSense sees cloudflared's address, not the user's. Configure **cloudflared source** with that address:

- `127.0.0.1` (and `::1`) if cloudflared runs on pfSense itself
- the host's LAN IP if it runs elsewhere

The **This request** panel on the Settings tab shows what pfSense sees, which helps you find it.

- `CF-Connecting-IP` is read **only** when the TCP peer matches a configured cloudflared source. From any other peer the header is ignored, because anyone could forge it. The trusted value is used for logging, for example: `webauthn: passkey verification failed for user 'admin' (1/5): Signature verification failed from 203.0.113.9 (via cloudflared 127.0.0.1)`.
- WebAuthn events are logged with the **USER** facility, under Status > System Logs > System > General (search for `webauthn`). They never use the `webConfigurator authentication error ... from:` format that sshguard watches. A failed passkey therefore never puts cloudflared's address into the lockout table, which would lock out every tunnel user. Repeated failures are limited per session instead: after 5 failures the session is destroyed and the password must be entered again.
- **Password** failures are still logged by pfSense itself, in sshguard's format, with cloudflared's address. That **would** lock out everyone. Add the cloudflared address to **System > Advanced > Admin Access > Login Protection > Pass list**. Cloudflare Access is then your brute-force protection in front of the password.

### DNS rebind and HTTP_REFERER checks

pfSense rejects requests whose `Host` header, or `Referer` host, it does not recognise. Under **System > Advanced > Admin Access > Alternate Hostnames**, add:

```
pfsense.example.com
```

Also add any LAN hostname you use, e.g. `pfsense.lan.example.com`. Without this you get "Potential DNS Rebind attack detected" or "An HTTP_REFERER was detected other than what is defined". The Settings tab warns about any allowed-origin host that is missing from this list.

Depending on the ingress configuration, cloudflared may send pfSense the origin service address (for example `127.0.0.1`) as `Host` instead of the public hostname. The browser still sends the public hostname as `Referer`, so it must be in Alternate Hostnames either way. The package never relies on `Host`: the browser checks its own origin against the allowed list before starting a ceremony, and the server checks the origin in `clientDataJSON`.

### cloudflared ingress tips

```yaml
ingress:
  - hostname: pfsense.example.com
    path: (?i)xmlrpc             # unanchored: also matches //xmlrpc.php, /./xmlrpc.php, /XMLRPC.php
    service: http_status:404     # XMLRPC uses HTTP basic auth (password only); never expose it
  - hostname: pfsense.example.com
    service: https://127.0.0.1:443
    originRequest:
      noTLSVerify: true          # pfSense's self-signed GUI certificate
  - service: http_status:404
```

`/xmlrpc.php` (HA sync) authenticates with a password over HTTP basic auth and does not go through the GUI login, so the WebAuthn step cannot protect it. The package therefore refuses XMLRPC requests that arrive from a cloudflared source address or carry proxy headers, whether or not the second factor is enabled. HA peers connect directly and are unaffected. Block it on the tunnel as well, with the **unanchored** rule shown above: an anchored `^/xmlrpc\.php` rule misses paths such as `//xmlrpc.php`, which pfSense's web server still serves.

If the GUI runs over plain HTTP, pfSense does not set the `Secure` flag on its session cookie. The browser still talks HTTPS to Cloudflare, but keeping the GUI on HTTPS (with `noTLSVerify`) is preferable.

## Local fallback

Passkeys are bound to a domain name. They cannot work when you open the GUI by IP address (`https://192.168.1.1`). There are two options, and they can be combined:

1. **Trusted networks** (setting): source networks, e.g. `192.168.1.0/24`, that skip the WebAuthn step. They can only be saved once the **cloudflared source** is set. Traffic from a cloudflared source address, or any request carrying Cloudflare or proxy headers (`CF-Connecting-IP`, `X-Forwarded-For`, `Forwarded`, `X-Real-IP`), is **never** exempt. This holds even when cloudflared itself sits inside a trusted network (on the LAN, or on pfSense at 127.0.0.1). Otherwise every Internet user would inherit the LAN's exemption.
2. **Parent-domain RP ID**: set the RP ID to `example.com` and the allowed origins to:
   ```
   https://pfsense.example.com
   https://pfsense.lan.example.com
   ```
   One passkey then works on both hostnames. The LAN hostname needs:
   - local DNS pointing it at pfSense (DNS Resolver host override)
   - HTTPS with a certificate the browser trusts (for example from the ACME package with a DNS-01 challenge), because browsers only offer WebAuthn on secure origins
   - an entry in Alternate Hostnames

   Changing the RP ID invalidates passkeys registered under the old one. The passkey list marks them as not matching.

When you reach the GUI by an IP or another unlisted name from outside a trusted network, the gate explains that passkeys need one of the configured hostnames, and links to them.

## Setup order (avoid locking yourself out)

1. Install the package, then set the Alternate Hostnames and the Login Protection pass list.
2. Under **System > WebAuthn Passkeys > Settings**, set the RP ID, the allowed origins, the cloudflared source, and the trusted networks. Leave **Enforce** off, then enable.
3. Open the GUI on an allowed hostname, then **Passkeys > Register passkey**. Register at least two authenticators.
4. Turn on **Enforce**. Users without a passkey are then refused, except from trusted networks. The settings page refuses to save a change that would lock out the session making it.

Once a user has a passkey, adding another requires a session that signed in **with** a passkey. A password alone, even from a trusted network, cannot enrol an extra passkey. Removing a passkey ends the sessions it verified at their next request.

Recovery, if every passkey is lost: log in from a trusted network, remove the lost passkeys, then register a new one. Without a trusted network, run `/usr/local/pkg/webauthn/hook.php uninstall` from the console.

Usernames are matched case-insensitively (`Admin` and `admin` share passkeys), because LDAP and RADIUS accept either.

Users with the `page-all` privilege (admins) manage everyone's passkeys and the settings. Other users can register and remove only their own passkeys, if they are granted access to `system_webauthn.php`.

## Security notes and limits

**What is covered:** every web GUI page. That includes the lightweight status endpoints such as `getstats.php`, which use `auth_check.inc`: a hook makes them ignore the session's cached page privileges unless the session has passed the gate (or is exempt for this request). XMLRPC is refused when it arrives through the tunnel. Passkey registrations and removals, settings changes, and 5 failed passkey attempts after a correct password each raise a GUI notice. The notice is also sent by e-mail or another notification channel, if you have one configured.

**What is not covered:**
- `/xmlrpc.php` reached directly on the LAN (password only). It is refused through the tunnel.
- SSH and the console.
- Other services (VPN and similar).
- Add-on packages with their own authentication, such as a REST API package.

**When the second factor silently switches off (fail-open):**
- **The hook is missing.** This happens after a pfSense upgrade, until the boot script re-applies it, or if pfSense ever changes the code the hook is anchored to. Run `/usr/local/pkg/webauthn/hook.php status` after upgrades.
- **The settings are gone.** This happens when you restore a config backup taken before WebAuthn was enabled. The Passkeys tab then shows "disabled".

Errors inside the gate fail closed: the page does not load.

**Trusted networks** skip the passkey entirely. Anyone in them who knows a password can act as that user, and can register a first passkey for a user who has none. Keep the list as narrow as possible: your admin PC's address, or a management VLAN, rather than a whole LAN with guests and IoT devices.

**User verification:** *Required* makes the authenticator ask for a PIN or biometric on every use. Choose it if your authenticators support it.

**Updates run as root on your firewall.** Pin the download to a commit you have reviewed (`.../tar.gz/<commit-sha>`) instead of a branch. Protect the GitHub account that hosts the code with 2FA.

## Tests

```sh
php tests/run.php         # verifier, CBOR, policy, settings validation, authgui hook (79 checks)
php tests/gate_test.php   # end-to-end gate requests with a software authenticator (14 checks)
php tests/audit_test.php  # security audit regressions F1-F7, incl. the real patched auth_check.inc (47 checks)
```

`tests/fixtures/` holds pfSense's upstream `authgui.inc`, `auth_check.inc` and `xmlrpc.php` (Apache-2.0). The tests use them to check that every hook anchor matches and that each patched file still parses.
