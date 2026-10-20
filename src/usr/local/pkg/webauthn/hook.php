#!/usr/local/bin/php -f
<?php
/*
 * hook.php
 *
 * Usage: hook.php install | uninstall | status | ensure
 *
 *   install    patch authgui.inc, auth_check.inc and xmlrpc.php, and add
 *              the System menu entry
 *   uninstall  remove the patches and the menu entry
 *   status     exit 0 if every hook is in place and current, 1 if not
 *   ensure     (re-)apply missing or outdated hooks (run at boot, since a
 *              pfSense upgrade replaces the patched files)
 *
 * Licensed under the Apache License, Version 2.0.
 */

require_once('config.inc');
require_once('util.inc');
require_once(__DIR__ . '/hook.inc');

define('WEBAUTHN_MENU_URL', '/system_webauthn.php');

/* Apply the current hook to one target. Returns true when it is in place. */
function patch_target(string $target): bool {
	$file = webauthn_hook_targets()[$target]['file'];
	$src = @file_get_contents($file);
	if ($src === false) {
		fwrite(STDERR, "Cannot read {$file}\n");
		return false;
	}
	if (webauthn_hook_current($src, $target)) {
		return true;
	}
	$new = webauthn_hook_apply($src, $target);
	if ($new === null) {
		fwrite(STDERR, "Could not find the hook anchor in {$file}; not patched.\n");
		syslog(LOG_USER | LOG_ERR, "webauthn: could not patch {$file}; WebAuthn protection is incomplete");
		return false;
	}
	if (!webauthn_hook_present($src) && !file_exists($file . '.webauthn-orig')) {
		copy($file, $file . '.webauthn-orig');
	}
	$tmp = $file . '.webauthn-tmp';
	file_put_contents($tmp, $new);
	exec('/usr/local/bin/php -l ' . escapeshellarg($tmp) . ' 2>&1', $out, $rc);
	if ($rc != 0) {
		unlink($tmp);
		fwrite(STDERR, "Patched {$file} failed lint; not installed:\n" . implode("\n", $out) . "\n");
		return false;
	}
	chmod($tmp, fileperms($file) & 0777);
	rename($tmp, $file);
	syslog(LOG_USER | LOG_NOTICE, "webauthn: hook installed in {$file}");
	return true;
}

function patch_all(): bool {
	$ok = true;
	foreach (array_keys(webauthn_hook_targets()) as $target) {
		$ok = patch_target($target) && $ok;
	}
	return $ok;
}

function unpatch_all(): void {
	foreach (webauthn_hook_targets() as $t) {
		$src = @file_get_contents($t['file']);
		if ($src !== false && webauthn_hook_present($src)) {
			file_put_contents($t['file'], webauthn_hook_remove($src));
		}
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
	$ok = patch_all();
	set_menu(true);
	echo $ok ? "WebAuthn hooks installed.\n" : "WebAuthn hooks INCOMPLETE, see errors above.\n";
	exit($ok ? 0 : 1);
case 'uninstall':
	unpatch_all();
	set_menu(false);
	echo "WebAuthn hooks removed. Passkeys and settings remain in config.xml.\n";
	break;
case 'ensure':
	exit(patch_all() ? 0 : 1);
case 'status':
	$ok = true;
	foreach (webauthn_hook_targets() as $target => $t) {
		$src = (string)@file_get_contents($t['file']);
		$state = webauthn_hook_current($src, $target) ? 'present' : (webauthn_hook_present($src) ? 'OUTDATED' : 'MISSING');
		$ok = $ok && $state === 'present';
		echo "{$target}: hook {$state}\n";
	}
	exit($ok ? 0 : 1);
default:
	fwrite(STDERR, "usage: {$argv[0]} install|uninstall|status|ensure\n");
	exit(2);
}
