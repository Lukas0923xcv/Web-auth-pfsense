#!/bin/sh
# Re-apply the WebAuthn hooks at boot. pfSense upgrades replace the
# patched files, which would silently drop the second factor. (A cron
# job does the same every minute, for boots that skip this script.)
case "$1" in
start|"")
	/usr/local/bin/php -f /usr/local/pkg/webauthn/hook.php ensure >/dev/null 2>&1
	;;
esac
