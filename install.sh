#!/bin/sh
# Install the pfSense WebAuthn second factor. Run as root on pfSense
# from a checkout of this repository.
set -e
cd "$(dirname "$0")"

for f in \
	usr/local/pkg/webauthn/cbor.inc \
	usr/local/pkg/webauthn/webauthn_lib.inc \
	usr/local/pkg/webauthn/webauthn.inc \
	usr/local/pkg/webauthn/gate.inc \
	usr/local/pkg/webauthn/hook.inc \
	usr/local/pkg/webauthn/xmlrpc_guard.inc \
	usr/local/pkg/webauthn/hook.php \
	usr/local/pkg/webauthn/VERSION \
	usr/local/www/system_webauthn.php \
	usr/local/www/webauthn/webauthn.js \
	usr/local/etc/rc.d/webauthn_hook.sh
do
	install -d -o root -g wheel -m 0755 "/$(dirname "$f")"
	install -o root -g wheel -m 0644 "src/$f" "/$f"
done
chmod 0755 /usr/local/etc/rc.d/webauthn_hook.sh /usr/local/pkg/webauthn/hook.php

for f in /usr/local/pkg/webauthn/*.inc /usr/local/pkg/webauthn/hook.php /usr/local/www/system_webauthn.php; do
	/usr/local/bin/php -l "$f" >/dev/null
done

/usr/local/bin/php -f /usr/local/pkg/webauthn/hook.php install
echo "Open System > WebAuthn Passkeys to configure."
