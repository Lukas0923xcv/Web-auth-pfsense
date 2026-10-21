# Upgrade notes

## Updating the package

Run the install command from the [README](../README.md) again: it installs the pinned version over the old one and keeps your settings and passkeys. Then check:

```sh
/usr/local/pkg/webauthn/hook.php status
```

The first line shows the version; the other five must say `present`. After an update, every session has to confirm with its passkey once.

## Upgrading pfSense

A pfSense upgrade replaces the files the hooks live in (`/etc/inc/authgui.inc`, `/etc/inc/auth_check.inc`, `/usr/local/www/xmlrpc.php`). The package puts the hooks back:

- every minute, from cron, while the system runs;
- at boot, from an early shell command, before the web GUI starts.

So the passkey step can be missing for **at most one minute** after the upgrade replaces the files, or until the reboot if that comes sooner (see [SECURITY.md](../SECURITY.md) for the exact window). After every pfSense upgrade:

1. Run `/usr/local/pkg/webauthn/hook.php status`. Every line must say `present`.
2. If a line says `MISSING` and the bell icon shows "Could not patch ... (hook anchor not found)", the new pfSense version changed the code a hook attaches to. The GUI then has no second factor. Check the repository for a newer version, or turn the second factor off until there is one. See [TROUBLESHOOTING.md](TROUBLESHOOTING.md#a-hook-is-outdated-or-missing).

The CI checks the hooks against the files of pfSense CE 2.8.1 on every push, and weekly against pfSense's development branch, so a coming change usually shows up before a release.

## Notes per version

### 1.2.0

- **Failed-attempt limit across sessions.** 10 failed passkey attempts for one account from one client address, in any number of sessions, lock that address out of the account's passkey step for 15 minutes (`/conf/webauthn_failures.json`). The 5-per-session limit stays. If that file is damaged, no passkey sign-in works until it is fixed: `rm /conf/webauthn_failures.json`.
- **The firewall's own addresses are never a trusted network.** A connection from loopback or from one of the firewall's interface addresses no longer skips the passkey step, and is no longer allowed to use XMLRPC through the trusted networks (list it under XMLRPC peers if you need that). This closes a gap with Cloudflare private-network (WARP) routes. If you reached the GUI through an SSH port forward (`ssh -L`, which arrives from 127.0.0.1) and relied on a trusted network, you now need the passkey, so use a hostname from the allowed origins.
- **Removed passkeys are revoked by ID and key.** A removed passkey can no longer be registered again (register a new one instead). Entries written by older versions stay valid and revoke every key under their ID.
- **Backup flags:** an authenticator that reports "backed up" without "backup eligible" is refused (WebAuthn Level 3). Real authenticators do not do this.
- Uninstall now also removes the backups (`*.webauthn.orig`) once the original files are back.

### 1.1.0

- The hooks are re-applied every minute instead of every 5 minutes. `hook.php status` shows `cron: re-apply job OUTDATED` until you run the install command again.
- `webauthn.inc` was split into `webauthn.inc`, `storage.inc` and `challenge.inc`; the installer writes the new files first.
