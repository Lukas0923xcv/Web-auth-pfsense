#!/bin/sh
# Install the pfSense WebAuthn second factor. Run as root on pfSense
# from a checkout of this repository.
set -e
cd "$(dirname "$0")"

if [ "$(id -u)" -ne 0 ]; then
	echo "Run install.sh as root." >&2
	exit 1
fi
if [ ! -f /etc/inc/authgui.inc ] || [ ! -x /usr/local/bin/php ]; then
	echo "This does not look like pfSense (/etc/inc/authgui.inc or /usr/local/bin/php missing); nothing installed." >&2
	exit 1
fi

# New files first: webauthn.inc loads storage.inc and challenge.inc, so a
# GUI request during an update must never find webauthn.inc without them.
files="
	usr/local/pkg/webauthn/cbor.inc
	usr/local/pkg/webauthn/webauthn_lib.inc
	usr/local/pkg/webauthn/storage.inc
	usr/local/pkg/webauthn/challenge.inc
	usr/local/pkg/webauthn/webauthn.inc
	usr/local/pkg/webauthn/gate.inc
	usr/local/pkg/webauthn/hook.inc
	usr/local/pkg/webauthn/xmlrpc_guard.inc
	usr/local/pkg/webauthn/hook.php
	usr/local/pkg/webauthn/VERSION
	usr/local/www/system_webauthn.php
	usr/local/www/webauthn/webauthn.js
	usr/local/etc/rc.d/webauthn_hook.sh
"

# Check the whole download before changing anything on the system.
for f in $files; do
	if [ ! -f "src/$f" ]; then
		echo "src/$f is missing from the download; nothing installed." >&2
		exit 1
	fi
	case "$f" in
	*.inc|*.php)
		/usr/local/bin/php -l "src/$f" >/dev/null
		;;
	esac
done

for f in $files; do
	install -d -o root -g wheel -m 0755 "/$(dirname "$f")"
	install -o root -g wheel -m 0644 "src/$f" "/$f"
done
chmod 0755 /usr/local/etc/rc.d/webauthn_hook.sh /usr/local/pkg/webauthn/hook.php

/usr/local/bin/php -f /usr/local/pkg/webauthn/hook.php install
echo "Installed version $(cat /usr/local/pkg/webauthn/VERSION). Open System > WebAuthn Passkeys to configure."
