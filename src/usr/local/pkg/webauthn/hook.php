#!/usr/local/bin/php -f
<?php
/*
 * hook.php
 *
 * Usage: hook.php install | uninstall | status | ensure
 *
 *   install    patch authgui.inc and add the System menu entry
 *   uninstall  remove the patch and the menu entry
 *   status     exit 0 if the hook is in place, 1 if not
 *   ensure     re-apply the patch if missing (run at boot, since a
 *              pfSense upgrade replaces authgui.inc)
 *
 * Licensed under the Apache License, Version 2.0.
 */

require_once('config.inc');
require_once('util.inc');
require_once(__DIR__ . '/hook.inc');

define('WEBAUTHN_MENU_URL', '/system_webauthn.php');

function patch_authgui(): bool {
	$src = file_get_contents(WEBAUTHN_AUTHGUI);
	if ($src === false) {
		fwrite(STDERR, "Cannot read " . WEBAUTHN_AUTHGUI . "\n");
		return false;
	}
	if (webauthn_hook_present($src)) {
		return true;
	}
	$new = webauthn_hook_apply($src);
	if ($new === null) {
		fwrite(STDERR, "Could not find the session_auth() block in " . WEBAUTHN_AUTHGUI . "; not patched.\n");
		syslog(LOG_USER | LOG_ERR, 'webauthn: could not patch authgui.inc; the WebAuthn second factor is NOT active');
		return false;
	}
	copy(WEBAUTHN_AUTHGUI, WEBAUTHN_AUTHGUI . '.webauthn-orig');
	$tmp = WEBAUTHN_AUTHGUI . '.webauthn-tmp';
	file_put_contents($tmp, $new);
	exec('/usr/local/bin/php -l ' . escapeshellarg($tmp) . ' 2>&1', $out, $rc);
	if ($rc != 0) {
		unlink($tmp);
		fwrite(STDERR, "Patched authgui.inc failed lint; not installed:\n" . implode("\n", $out) . "\n");
		return false;
	}
	rename($tmp, WEBAUTHN_AUTHGUI);
	syslog(LOG_USER | LOG_NOTICE, 'webauthn: hook installed in authgui.inc');
	return true;
}

function unpatch_authgui(): void {
	$src = file_get_contents(WEBAUTHN_AUTHGUI);
	if ($src !== false && webauthn_hook_present($src)) {
		file_put_contents(WEBAUTHN_AUTHGUI, webauthn_hook_remove($src));
	}
}

function set_menu(bool $present): void {
	$menus = config_get_path('installedpackages/menu', []);
	$menus = is_array($menus) ? $menus : [];
	$menus = array_values(array_filter($menus, function ($m) {
		return ($m['url'] ?? '') !== WEBAUTHN_MENU_URL;
	}));
	if ($present) {
		$menus[] = ['name' => 'WebAuthn Passkeys', 'section' => 'System', 'url' => WEBAUTHN_MENU_URL];
	}
	config_set_path('installedpackages/menu', $menus);
	write_config($present ? 'WebAuthn: added menu entry' : 'WebAuthn: removed menu entry');
}

switch ($argv[1] ?? '') {
case 'install':
	if (!patch_authgui()) {
		exit(1);
	}
	set_menu(true);
	echo "WebAuthn hook installed.\n";
	break;
case 'uninstall':
	unpatch_authgui();
	set_menu(false);
	echo "WebAuthn hook removed. Passkeys and settings remain in config.xml.\n";
	break;
case 'ensure':
	exit(patch_authgui() ? 0 : 1);
case 'status':
	$ok = webauthn_hook_present((string)file_get_contents(WEBAUTHN_AUTHGUI));
	echo $ok ? "hook present\n" : "hook MISSING\n";
	exit($ok ? 0 : 1);
default:
	fwrite(STDERR, "usage: {$argv[0]} install|uninstall|status|ensure\n");
	exit(2);
}
