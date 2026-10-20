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
cd /root && fetch -o webauthn.tar.gz https://codeload.github.com/Lukas0923xcv/Web-auth-pfsense/tar.gz/refs/heads/claude/vigilant-cray-p2utgq
rm -rf Web-auth-pfsense-* && tar xzf webauthn.tar.gz && cd Web-auth-pfsense-* && sh install.sh
```

The installer copies the files, lint-checks them, patches `authgui.inc` (keeping a copy at `authgui.inc.webauthn-orig`), and adds **System > WebAuthn Passkeys** to the menu. The second factor stays **disabled** until you turn it on.

- Check the hook: `/usr/local/pkg/webauthn/hook.php status`
- Uninstall: `sh uninstall.sh`. Passkeys and settings stay in `config.xml`.
- Upgrades: a pfSense upgrade replaces `authgui.inc`. `/usr/local/etc/rc.d/webauthn_hook.sh` re-applies the hook at every boot, and pfSense upgrades reboot. Still, run `hook.php status` after upgrading. If the anchor ever changes, the hook is **not** applied, and an error is logged with the text `webauthn: could not patch authgui.inc`.

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
    path: ^/xmlrpc\.php
    service: http_status:404     # XMLRPC uses HTTP basic auth (password only); never expose it
  - hostname: pfsense.example.com
    service: https://127.0.0.1:443
    originRequest:
      noTLSVerify: true          # pfSense's self-signed GUI certificate
  - service: http_status:404
```

`/xmlrpc.php` (HA sync) authenticates with a password over HTTP basic auth and does not go through the GUI login, so the WebAuthn step cannot protect it. Block it on the tunnel as shown above.

If the GUI runs over plain HTTP, pfSense does not set the `Secure` flag on its session cookie. The browser still talks HTTPS to Cloudflare, but keeping the GUI on HTTPS (with `noTLSVerify`) is preferable.

## Local fallback

Passkeys are bound to a domain name. They cannot work when you open the GUI by IP address (`https://192.168.1.1`). There are two options, and they can be combined:

1. **Trusted networks** (setting): source networks, e.g. `192.168.1.0/24`, that skip the WebAuthn step. Traffic from a cloudflared source address, or any request carrying Cloudflare or proxy headers (`CF-Connecting-IP`, `X-Forwarded-For`, `Forwarded`, `X-Real-IP`), is **never** exempt. This holds even when cloudflared itself sits inside a trusted network (on the LAN, or on pfSense at 127.0.0.1). Otherwise every Internet user would inherit the LAN's exemption.
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

Recovery, if every passkey is lost: log in from a trusted network and register a new one. Without a trusted network, run `/usr/local/pkg/webauthn/hook.php uninstall` from the console.

Users with the `page-all` privilege (admins) manage everyone's passkeys and the settings. Other users can register and remove only their own passkeys, if they are granted access to `system_webauthn.php`.

## Tests

```sh
php tests/run.php        # verifier, CBOR, policy, settings validation, authgui hook (79 checks)
php tests/gate_test.php  # end-to-end gate requests with a software authenticator (13 checks)
```

`tests/fixtures/authgui.inc` is pfSense's upstream file (Apache-2.0), used to check that the hook anchor matches.
