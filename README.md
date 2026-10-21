# pfSense WebAuthn second factor

[![tests](https://github.com/Lukas0923xcv/web-auth-pfsense/actions/workflows/tests.yml/badge.svg)](https://github.com/Lukas0923xcv/web-auth-pfsense/actions/workflows/tests.yml)

Adds a passkey / security-key (WebAuthn) step after the normal password login on the pfSense web GUI. Target: pfSense CE 2.8.1. Built for access through a Cloudflare Tunnel, but it also works on the LAN.

> **Review status:** written with an AI assistant and not yet audited by a human. Read [SECURITY.md](SECURITY.md) for what it protects against and what it does not, and run [docs/VM-TEST.md](docs/VM-TEST.md) on a test VM before you rely on it.

## Install / update

Run this **single line** on the pfSense (console option 8, SSH, or **Diagnostics > Command Prompt**). It must not be split. The same command updates an existing install and keeps your settings and passkeys.

It installs version <!-- pinned-version -->1.1.0<!-- /pinned-version -->, the commit of that release. `sha256 -c` checks that the download is exactly that commit (the same hash as the release's `SHA256SUMS`), so nothing pushed later can change what this command installs.

```sh
cd /root && fetch -o webauthn.tar.gz https://codeload.github.com/Lukas0923xcv/web-auth-pfsense/tar.gz/2b2de835efc356145924b979552df32c34fe5fd3 && sha256 -c f40669427add868fad11dfe60890d36e0bfd98643e99140762834dacd681d821 webauthn.tar.gz && rm -rf [Ww]eb-auth-pfsense-* && tar xzf webauthn.tar.gz && cd web-auth-pfsense-* && sh install.sh
```

When it worked, the output ends with `Installed version ...`. Then check:

```sh
/usr/local/pkg/webauthn/hook.php status
```

The first line shows the version; the other five must say `present`. The second factor stays **off** until you enable it: follow [docs/SETUP.md](docs/SETUP.md), in its order, so you cannot lock yourself out.

## Remove

```sh
cd /root/[Ww]eb-auth-pfsense-* && sh uninstall.sh
```

Without the downloaded folder: `/usr/local/pkg/webauthn/hook.php uninstall`, then `rm -rf /usr/local/pkg/webauthn /usr/local/www/webauthn /usr/local/www/system_webauthn.php /usr/local/etc/rc.d/webauthn_hook.sh`. Passkeys and settings stay in `config.xml`.

## Documentation

- [docs/SETUP.md](docs/SETUP.md): setup, Cloudflare Tunnel, trusted networks, HA.
- [docs/UPGRADE.md](docs/UPGRADE.md): updating the package, upgrading pfSense, notes per version. [CHANGELOG.md](CHANGELOG.md) lists all changes.
- [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md): locked out, hook OUTDATED/MISSING, checksum mismatch, wrong hostname, LDAP spelling refused.
- [docs/VM-TEST.md](docs/VM-TEST.md): test it on a pfSense VM, step by step.
- [SECURITY.md](SECURITY.md): threat model, the upgrade window, review findings, reporting a vulnerability. Reviewers: [docs/REVIEW-GUIDE.md](docs/REVIEW-GUIDE.md).
- [tests/README.md](tests/README.md) and [docs/RELEASING.md](docs/RELEASING.md): for contributors.

## License

Apache License 2.0, see [LICENSE](LICENSE).
