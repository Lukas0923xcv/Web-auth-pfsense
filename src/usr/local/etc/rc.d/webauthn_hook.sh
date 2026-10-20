#!/bin/sh
# Re-apply the WebAuthn hook at boot. pfSense upgrades replace
# /etc/inc/authgui.inc, which would silently drop the second factor.
/usr/local/bin/php -f /usr/local/pkg/webauthn/hook.php ensure >/dev/null 2>&1
