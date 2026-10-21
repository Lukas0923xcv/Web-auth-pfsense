# Test on a pfSense VM

Run this on a throw-away **pfSense CE 2.8.1** VM before you rely on the package. It takes about 45 minutes. Each step says what you should see. When you are done, open an issue titled **"VM test results: pfSense CE 2.8.1, version X.Y.Z"** with the output of every step that did not match (or "all steps matched").

## What you need

- A pfSense CE 2.8.1 VM (VirtualBox, Proxmox, ...) with LAN `192.168.1.1/24`, and a client VM or PC on that LAN, here `192.168.1.100`.
- Console access to the VM (the hypervisor console is enough).
- A hostname for the GUI that the client resolves to `192.168.1.1`, here `pfsense.home.arpa` (add it to the client's hosts file).
- A certificate for it that the client's browser trusts. In pfSense: **System > Cert. Manager > CAs > Add** (create an internal CA), then **Certificates > Add** (server certificate, SAN `pfsense.home.arpa`). Select it in **System > Advanced > Admin Access > SSL/TLS Certificate**, and import the CA into the client's browser.
- An authenticator: a security key, a phone, or Chrome's virtual authenticator (DevTools > More tools > WebAuthn > Enable virtual authenticator environment > Add, with "Supports user verification" ticked).

## 1. Install

On the VM console (option 8, shell), paste the install command from the README as one line.

Expected: the last two lines are

```
WebAuthn hooks installed.
Installed version X.Y.Z. Open System > WebAuthn Passkeys to configure.
```

## 2. Status

```sh
/usr/local/pkg/webauthn/hook.php status; echo "exit $?"
```

Expected, exactly (with your version):

```
version: X.Y.Z
authgui: hook present
auth_check: hook present
xmlrpc: hook present
cron: re-apply job present
boot: earlyshellcmd present
exit 0
```

## 3. Configure

In the GUI at `https://pfsense.home.arpa` (signed in as admin):

1. **System > Advanced > Admin Access > Alternate Hostnames**: `pfsense.home.arpa`. Save.
2. **System > WebAuthn Passkeys > Settings**: RP ID `pfsense.home.arpa`, Allowed origins empty, cloudflared source `127.0.0.1`, Trusted networks empty, User verification `Preferred`, Enforce off, Enable ticked. Save.

Expected: "Settings saved." The bottom of the page shows "pfSense WebAuthn Passkeys, version X.Y.Z".

## 4. Register two passkeys

**System > WebAuthn Passkeys > Passkeys**: type a name, click **Register passkey**, confirm in the browser. Repeat with a second authenticator (or a second virtual one).

Expected: "Passkey "…" registered." twice; the table lists both with RP ID `pfsense.home.arpa`. The bell icon shows a notice for each registration.

## 5. Sign in with a passkey

Sign out, sign in with the admin password.

Expected: a "Passkey verification" page appears instead of the dashboard, the browser asks for the passkey, and after confirming you get the dashboard. On the console:

```sh
grep 'webauthn:' /var/log/system.log | tail -n 3
```

shows `webauthn: user 'admin' verified with passkey from 192.168.1.100`.

## 6. Wrong hostname

Open `https://192.168.1.1` (by IP) in a new private window and sign in with the password.

Expected: the passkey page says "Passkeys only work on a configured hostname, not on an IP address or other name. Open the GUI at:" with a link to `https://pfsense.home.arpa/`. No dashboard.

## 7. Enforce, and a user without a passkey

1. **System > User Manager > Add**: user `test`, any password, group `admins`. Save.
2. **System > WebAuthn Passkeys > Settings**: tick **Enforce**, save.
3. In a private window, sign in as `test`.

Expected: "This account has no registered passkey, and a passkey is required from this network." Only **Sign out** works. The log has `webauthn: user 'test' has no registered passkey and enforcement is on; access refused from 192.168.1.100`.

## 8. Failed attempts

Sign in as admin in a private window. On the passkey page, cancel the browser's passkey prompt (cancelling sends nothing), open the browser's developer console (F12) and submit an empty answer, which counts as a failed attempt:

```js
document.getElementById('webauthn-form').submit()
```

Do this five times (after each, the page comes back with "Passkey verification failed. Try again.").

Expected: after the fifth failure you are signed out. The log shows `passkey verification failed for user 'admin' (1/5)` up to `(5/5)` and `session ended`; the bell icon shows "5 failed passkey attempts for user "admin" …".

Sign in again and fail five more times (10 in all from this address).

Expected: the next sign-in from `192.168.1.100` shows "Too many failed passkey attempts for this account. Try again in 15 minutes, or sign in from a trusted network." Clear it on the console with `rm /conf/webauthn_failures.json` and check that the passkey works again.

## 9. XMLRPC is refused

From the client:

```sh
curl -sk -u admin:YOURPASSWORD https://pfsense.home.arpa/xmlrpc.php \
  -d '<?xml version="1.0"?><methodCall><methodName>pfsense.host_firmware_version</methodName></methodCall>'
```

Expected: `XMLRPC is not available from this address.` (HTTP 403), and in the log `refused XMLRPC request: the source is not an XMLRPC peer or on a trusted network`.

## 10. Trusted network

**Settings**: Trusted networks `192.168.1.100/32`, save. Sign in as admin in a private window.

Expected: the dashboard appears without the passkey page. The log shows `user 'admin' skipped WebAuthn (trusted network) from 192.168.1.100`. Remove the trusted network again afterwards.

## 11. A pfSense upgrade replacing the files

Simulate it on the console by putting back the original `authgui.inc`:

```sh
cp /etc/inc/authgui.inc.webauthn.orig /etc/inc/authgui.inc
/usr/local/pkg/webauthn/hook.php status | grep authgui
sleep 65
/usr/local/pkg/webauthn/hook.php status | grep authgui
```

Expected: first `authgui: hook MISSING`, then, at most a minute later, `authgui: hook present`. The log shows `webauthn: hook installed in /etc/inc/authgui.inc`.

## 12. The same, followed by a reboot

```sh
cp /etc/inc/authgui.inc.webauthn.orig /etc/inc/authgui.inc && /sbin/reboot
```

Expected: during boot the console prints `Executing early shell commands...done.` before `Starting webConfigurator...`. After the boot, `hook.php status` shows every line `present`, and signing in asks for the passkey.

## 13. Remove

```sh
cd /root/[Ww]eb-auth-pfsense-* && sh uninstall.sh
grep -c 'pfSense-webauthn hook' /etc/inc/authgui.inc /etc/inc/auth_check.inc /usr/local/www/xmlrpc.php
ls /etc/inc/*.webauthn.orig /usr/local/www/*.webauthn.orig
```

Expected: `WebAuthn hooks removed. Passkeys and settings remain in config.xml.`, then `0` for each file, and `No such file or directory` for the backups. Signing in needs only the password again, and **System > WebAuthn Passkeys** is gone from the menu.
