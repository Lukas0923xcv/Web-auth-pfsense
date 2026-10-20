#!/bin/sh
# Remove the pfSense WebAuthn second factor. Passkeys and settings stay
# in config.xml under installedpackages/webauthn.
set -e
/usr/local/bin/php -f /usr/local/pkg/webauthn/hook.php uninstall
rm -f /usr/local/etc/rc.d/webauthn_hook.sh /usr/local/www/system_webauthn.php
rm -rf /usr/local/pkg/webauthn /usr/local/www/webauthn
