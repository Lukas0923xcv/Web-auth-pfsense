# pfSense WebAuthn second factor

[![tests](https://github.com/Lukas0923xcv/web-auth-pfsense/actions/workflows/tests.yml/badge.svg)](https://github.com/Lukas0923xcv/web-auth-pfsense/actions/workflows/tests.yml)

Adds a passkey / security-key (WebAuthn) step after the normal password login on the pfSense web GUI. Target: pfSense CE 2.8.1. Built for access through a Cloudflare Tunnel, but it also works on the LAN.

> **Review status:** written with an AI assistant and not yet audited by a human. Read [SECURITY.md](SECURITY.md) for what it protects against, what it does not, and how to report a problem. Try it on a test VM before your production firewall.

## Install / update

Run this **single line** on the pfSense (console option 8, SSH, or paste it into **Diagnostics > Command Prompt**). Paste it as one line: it must not be split. The same command updates an existing install and keeps your settings and passkeys.

It installs version <!-- pinned-version -->1.1.0<!-- /pinned-version -->, fixed to one commit. `sha256 -c` checks that the download is exactly that commit, so nothing pushed to the repository later can change what this command installs.

```sh
cd /root && fetch -o webauthn.tar.gz https://codeload.github.com/Lukas0923xcv/web-auth-pfsense/tar.gz/2b2de835efc356145924b979552df32c34fe5fd3 && sha256 -c f40669427add868fad11dfe60890d36e0bfd98643e99140762834dacd681d821 webauthn.tar.gz && rm -rf [Ww]eb-auth-pfsense-* && tar xzf webauthn.tar.gz && cd web-auth-pfsense-* && sh install.sh
```

When it worked, the output ends with `Installed version ...`. If the output is empty or shows an error, it did not install. If only the checksum fails, do not install: open an issue.

Then check that everything is in place. The first line shows the installed version, the other five must say `present` (`OUTDATED` means: run the install command again):

```sh
/usr/local/pkg/webauthn/hook.php status
```

The version is also shown at the bottom of **System > WebAuthn Passkeys**.

The second factor stays **off** until you enable it in **System > WebAuthn Passkeys > Settings**. After an update every session has to confirm with its passkey once.

The installer runs as root. Before you run it, you can read exactly what it installs: the code of the pinned commit is at `https://github.com/Lukas0923xcv/web-auth-pfsense/tree/<commit ID from the command>`.

## Remove

```sh
cd /root/[Ww]eb-auth-pfsense-* && sh uninstall.sh
```

Without the downloaded folder, the same steps by hand:

```sh
/usr/local/bin/php -f /usr/local/pkg/webauthn/hook.php uninstall
rm -f /usr/local/etc/rc.d/webauthn_hook.sh /usr/local/www/system_webauthn.php
rm -rf /usr/local/pkg/webauthn /usr/local/www/webauthn
```

Passkeys and settings stay in `config.xml`; the counters and lists in `/conf/webauthn_*` stay too (delete them only if you do not plan to reinstall).

## Setup (in this order, to avoid locking yourself out)

1. Install. Then, in pfSense:
   - **System > Advanced > Admin Access > Alternate Hostnames**: add your public hostname (e.g. `pfsense.example.com`) and any LAN hostname.
   - **Login Protection > Pass list**: add the address cloudflared connects from, or one wrong password locks out every tunnel user.
2. **System > WebAuthn Passkeys > Settings**: set the RP ID (public hostname, or its parent domain), the allowed origins, the **cloudflared source** (`127.0.0.1` if cloudflared runs on pfSense, else its LAN IP) and, if you use it, the trusted networks. Leave **Enforce** off and enable.
3. Open the GUI on an allowed hostname, **Passkeys > Register passkey**. Register at least two authenticators.
4. Turn **Enforce** on: users without a passkey are then refused (except from trusted networks). **With LDAP or RADIUS, always turn Enforce on**, because a directory can accept other spellings of a username than the one a passkey was registered for.

If you use **HA**, enter the partner's sync address under **XMLRPC peers** (on both nodes) before enabling, or configuration sync stops.

## Cloudflare Tunnel

Passkeys need the public hostname, not an IP. The origin and RP ID come from the hostname the browser used, never from how cloudflared reaches pfSense. Block XMLRPC and php-fpm's status page on the tunnel:

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

## Trusted networks and recovery

- **Trusted networks** skip the passkey (e.g. a management VLAN). Keep them narrow: an admin session there is effectively root. Tunnel traffic is never exempt, even if cloudflared sits inside one.
- To use passkeys on the LAN too, set the RP ID to the parent domain (`example.com`) and list both hostnames as allowed origins; the LAN hostname needs trusted HTTPS.
- **All passkeys lost:** an admin logs in from a trusted network, removes the lost passkeys and registers a new one. Without a trusted network, run `/usr/local/pkg/webauthn/hook.php uninstall` on the console.

## Good to know

- **Not covered:** SSH and the console, other services (VPN etc.), packages with their own login. XMLRPC (`/xmlrpc.php`) uses a password only; while the second factor is on it is refused except from XMLRPC peers and trusted networks.
- **Protection can switch off** if the hook is missing: during a pfSense upgrade until the next boot or cron run (at most 1 minute), or if pfSense changes the code the hook is anchored to (a GUI notice is raised). Run `hook.php status` after every upgrade or config restore.
- **A passkey belongs to the exact username.** Removing a passkey signs out the sessions it verified. A verification expires after 12 hours.
- Passkeys and settings live in `config.xml` (included in backups). Counters and the list of removed passkeys are in `/conf`, not in backups.
- If the package files are removed without the uninstaller, the GUI stops working (fail closed) instead of skipping the passkey step.

## Before you rely on it

1. **Test on a pfSense VM first.** Check that each of these is refused: the right password without a passkey (with Enforce on); the GUI by IP address instead of the hostname; `/xmlrpc.php` through the tunnel. Then upgrade pfSense on the VM and run `hook.php status`.
2. **Keep a way back in:** console or SSH access, and the uninstall command above.
3. **Run the tests** if you change anything: `sh tests/run_all.sh` (PHP 8.2+ with openssl, sodium, intl and mbstring). GitHub runs them on every push.

## For maintainers

To publish a new version: bump `src/usr/local/pkg/webauthn/VERSION`, push, wait for the tests to pass, then run `sh tools/pin_install.sh <full commit ID>` and commit the README change it makes.

## License

Apache License 2.0, see [LICENSE](LICENSE).
