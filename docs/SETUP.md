# Setup

Do the steps in this order, so you cannot lock yourself out.

## 1. Before you enable anything

In pfSense:

- **System > Advanced > Admin Access > Alternate Hostnames**: add your public hostname (for example `pfsense.example.com`) and any LAN hostname. Otherwise pfSense's DNS-rebind and HTTP_REFERER checks reject them.
- **System > Advanced > Admin Access > Login Protection > Pass list**: add the address cloudflared connects from. Otherwise one wrong password locks out every tunnel user, because they all arrive from that address.
- With **HA**: in **System > WebAuthn Passkeys > Settings > XMLRPC peers**, enter the partner's sync address on both nodes. Otherwise configuration sync stops once the second factor is on.

## 2. Settings

**System > WebAuthn Passkeys > Settings**:

| Setting | What to enter |
|---|---|
| RP ID | The public hostname (`pfsense.example.com`), or its parent domain (`example.com`) to use one passkey on the public and a LAN hostname. Changing it later invalidates existing passkeys. |
| Allowed origins | One per line, `https://` and under the RP ID. Empty means `https://<RP ID>`. |
| cloudflared source | `127.0.0.1` if cloudflared runs on pfSense, otherwise its LAN IP. |
| Trusted networks | Optional: networks that skip the passkey (for example a management VLAN). Keep them narrow: an admin session there is effectively root. |
| User verification | `Preferred` unless you want a PIN or biometric every time (`Required`). |
| Enforce | Leave **off** for now. |

Tick **Enable** and save. The page refuses to save settings that would lock out the session you are saving from.

## 3. Register passkeys

Open the GUI on an allowed hostname (not by IP address), go to **System > WebAuthn Passkeys > Passkeys** and click **Register passkey**. Register **at least two** authenticators, so losing one is not a lockout.

## 4. Enforce

Turn **Enforce** on: users without a passkey are then refused, except from trusted networks. **With LDAP or RADIUS, always turn Enforce on**: a directory may accept other spellings of a username than the one a passkey was registered for.

## Cloudflare Tunnel

Passkeys need the public hostname, not an IP address. The origin and RP ID come from the hostname the browser used, never from how cloudflared reaches pfSense. Block XMLRPC and php-fpm's status page on the tunnel:

```yaml
ingress:
  - hostname: pfsense.example.com
    path: (?i)xmlrpc
    service: http_status:404
  - hostname: pfsense.example.com
    path: (?i)^[/.]*status/?$
    service: http_status:404
  - hostname: pfsense.example.com
    service: https://127.0.0.1:443
    originRequest:
      noTLSVerify: true
  - service: http_status:404
```

**Private network routes (WARP to a LAN IP)** carry plain TCP, with no headers to tell them from LAN traffic. Requests from the firewall's own addresses (loopback, its interface addresses) never get the trusted-network exemption, which covers cloudflared running on pfSense. If cloudflared runs on another host and also routes private networks, enter that host's address as the cloudflared source, or keep its routes off the GUI.

## Trusted networks and the LAN

- Tunnel traffic is never exempt, even if cloudflared sits inside a trusted network.
- To use passkeys on the LAN too, set the RP ID to the parent domain (`example.com`) and list both hostnames as allowed origins. The LAN hostname needs a certificate the browser trusts.

## Good to know

- **Not covered:** SSH and the console, other services (VPN and so on), packages with their own login. XMLRPC (`/xmlrpc.php`) uses only a password; while the second factor is on, it is refused except from XMLRPC peers and trusted networks.
- **A passkey belongs to the exact username.** Removing a passkey signs out the sessions it verified. A verification lasts at most 12 hours.
- **Failed attempts:** 5 failed passkey attempts end the session. 10 failed attempts for one account from one address, over any number of sessions, lock that address out of the account's passkey step for 15 minutes. Other addresses and trusted networks are not affected.
- Passkeys and settings live in `config.xml`, so they are in backups. Counters, attempt counts and the list of removed passkeys are in `/conf/webauthn_*`, not in backups.
- If the package files are removed without the uninstaller, the GUI stops working (fail closed) instead of skipping the passkey step.
