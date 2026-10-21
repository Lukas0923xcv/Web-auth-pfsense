# Troubleshooting

Messages from the package appear in **Status > System Logs > System > General** (they start with `webauthn:`), and important events also under the bell icon (**Notices**). From a shell: `grep webauthn: /var/log/system.log`.

## Locked out

**You have the password but no working passkey (lost, broken, wrong RP ID).**

1. If you configured a trusted network: sign in from it (for example the management VLAN, by IP address). The passkey step is skipped there. Go to **System > WebAuthn Passkeys > Passkeys**, remove the lost passkeys and register a new one.
2. Without a trusted network, turn the second factor off from the console (option 8, or SSH):
   ```sh
   /usr/local/pkg/webauthn/hook.php uninstall
   ```
   This removes the hooks; passkeys and settings stay. Sign in with the password, fix the passkeys, then run the install command from the README again.

**"Too many failed passkey attempts for this account. Try again in ..."** Either 10 failed attempts came from your address (the passkey step is locked there for 15 minutes), or 30 came for the account from anywhere (it then takes one attempt every 20 seconds). Wait the time shown, or sign in from a trusted network. If this was not you, someone has your password: change it in **System > User Manager**. To clear the counts at once, from a shell:
```sh
rm /conf/webauthn_failures.json
```

**Every passkey sign-in fails and the log says a file in /conf "is damaged".** The package refuses passkeys rather than guess. Remove the damaged file named in the log, for example:
```sh
rm /conf/webauthn_failures.json       # failed-attempt counts
rm /conf/webauthn_signcount.json      # signature counters
```
Do not remove `/conf/webauthn_revoked.json` unless you also check the passkey list: it is what keeps removed passkeys from working.

## A hook is OUTDATED or MISSING

Run:
```sh
/usr/local/pkg/webauthn/hook.php status
```

| Output | Meaning | What to do |
|---|---|---|
| `...: hook OUTDATED` | An older version of the hook is in the file. | Run the install command from the README again. |
| `...: hook MISSING`, right after a pfSense upgrade | The upgrade replaced the file; cron puts the hook back within a minute. | Wait a minute and run `status` again, or run `/usr/local/pkg/webauthn/hook.php ensure`. |
| `...: hook MISSING`, and a notice "hook anchor not found" | The new pfSense version changed the code the hook attaches to. **The second factor is not active.** | Look for a newer package version. Until then, keep the GUI off the tunnel or turn the second factor off in **System > WebAuthn Passkeys > Settings**. |
| `...: hook MISSING`, and a notice "write failed" | The disk is full, or the file system is read-only. | Free space (`df -h`), then run `/usr/local/pkg/webauthn/hook.php ensure`. |
| `cron: re-apply job MISSING` or `OUTDATED`, `boot: earlyshellcmd MISSING` | A config restore or an older version. | Run the install command from the README again. |

## Checksum mismatch during install

The install command stops with `sha256: ... [ Failed ]` (or `SHA256 ... != ...`) and installs nothing. The download is not exactly the pinned version.

1. Run the command again: a broken download fails the same way.
2. If it fails again, do not install. Compare the hash with the one in the README of the repository and, once releases are published, with the `SHA256SUMS` file of the matching release on the **Releases** page. Open an issue with the output of:
   ```sh
   sha256 /root/webauthn.tar.gz
   ```

## "Passkeys only work on a configured hostname"

The GUI was opened on an IP address or a hostname that is not in **Allowed origins**. Passkeys are bound to a hostname, so the browser refuses them anywhere else.

- Open the GUI at one of the listed addresses (the page links them).
- To use another hostname, add it in **System > WebAuthn Passkeys > Settings > Allowed origins** (it must be under the RP ID) and in **System > Advanced > Admin Access > Alternate Hostnames**.
- A browser error "The operation is insecure" or "not supported" means the page is not on HTTPS with a trusted certificate.

## "The passkeys for this account are registered under another spelling of the username"

You signed in through LDAP or RADIUS with a different spelling of your name (other capitals, `user@domain`, `DOMAIN\user`) than the one your passkey was registered under. Passkeys belong to the exact name, so this spelling is refused rather than let through without a passkey.

- Click **Sign out**, then sign in with your username exactly as it appears in the **User** column of **System > WebAuthn Passkeys > Passkeys**.
- Names with `\` or `/` cannot hold passkeys through LDAP or RADIUS. Sign in with the plain name and register there.

## Configuration sync (HA) stopped

XMLRPC is refused while the second factor is on, except from **XMLRPC peers** and trusted networks. The log says `refused XMLRPC request`. Enter the partner's sync address under **System > WebAuthn Passkeys > Settings > XMLRPC peers** on both nodes.
