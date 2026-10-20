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
 *   status     exit 0 if every hook, the cron job and the boot command
 *              are in place, 1 if not
 *   ensure     (re-)apply missing or outdated hooks. Runs early at boot
 *              (earlyshellcmd, before the GUI starts), from the rc.d script,
 *              and every 5 minutes from cron, since a pfSense upgrade
 *              replaces the patched files.
 *
 * Licensed under the Apache License, Version 2.0.
 */

require_once('config.inc');
require_once('util.inc');
require_once(__DIR__ . '/hook.inc');

define('WEBAUTHN_MENU_URL', '/system_webauthn.php');
define('WEBAUTHN_CRON_COMMAND', '/usr/local/bin/php -f /usr/local/pkg/webauthn/hook.php ensure');
define('WEBAUTHN_UNINSTALLING', '/var/run/webauthn_uninstalling');

/*
 * Backups end in ".orig": xmlrpc.php lives in the web root, and nginx on
 * pfSense refuses to serve *.orig (and *.inc) files.
 */
function backup_path(string $file): string {
	return $file . '.webauthn.orig';
}

/*
 * Replace $file with $new. The data goes to a temp file first, is read
 * back and lint-checked, and only then renamed over $file. A failed write
 * (a full disk after an upgrade) must never install an empty or truncated
 * authgui.inc: php -l accepts an empty file, and an empty authgui.inc
 * would leave the GUI with no login at all.
 */
function replace_file(string $file, string $new): bool {
	$tmp = $file . '.webauthn-tmp-' . getmypid() . '.orig';
	@unlink($tmp);
	$fp = ($new === '') ? false : @fopen($tmp, 'x');
	$ok = $fp !== false && fwrite($fp, $new) === strlen($new) && fflush($fp) &&
	    (!function_exists('fsync') || fsync($fp));
	if ($fp !== false) {
		$ok = fclose($fp) && $ok;
	}
	if (!$ok || @file_get_contents($tmp) !== $new) {
		@unlink($tmp);
		fwrite(STDERR, "Could not write {$tmp} (disk full?); {$file} left unchanged.\n");
		return false;
	}
	exec('/usr/local/bin/php -l ' . escapeshellarg($tmp) . ' 2>&1', $out, $rc);
	if ($rc != 0) {
		@unlink($tmp);
		fwrite(STDERR, "Patched {$file} failed lint; not installed:\n" . implode("\n", $out) . "\n");
		return false;
	}
	chmod($tmp, fileperms($file) & 0777);
	if (!rename($tmp, $file)) {
		@unlink($tmp);
		fwrite(STDERR, "Could not replace {$file}.\n");
		return false;
	}
	return true;
}

/*
 * Report a target that could not be patched: syslog every time, and a
 * GUI notice (also e-mailed, if configured) once per boot.
 */
function hook_failed(string $target, string $why): void {
	$file = webauthn_hook_targets()[$target]['file'];
	syslog(LOG_USER | LOG_ERR, "webauthn: could not patch {$file} ({$why}); WebAuthn protection is incomplete");
	$flag = "/var/run/webauthn_hook_failed_{$target}";
	if (file_exists($flag)) {
		return;
	}
	@touch($flag);
	@include_once('notices.inc');
	if (function_exists('file_notice')) {
		file_notice('webauthn', "Could not patch {$file} ({$why}). The WebAuthn second factor is NOT fully active. " .
		    'Run /usr/local/pkg/webauthn/hook.php status from a shell.', 'WebAuthn');
	}
}

/* Apply the current hook to one target. Returns true when it is in place. */
function patch_target(string $target): bool {
	$file = webauthn_hook_targets()[$target]['file'];
	$src = @file_get_contents($file);
	if ($src === false) {
		fwrite(STDERR, "Cannot read {$file}\n");
		hook_failed($target, 'cannot read it');
		return false;
	}
	/* Older versions used a suffix that nginx would serve from the web root. */
	if (file_exists($file . '.webauthn-orig')) {
		if (!file_exists(backup_path($file))) {
			rename($file . '.webauthn-orig', backup_path($file));
		} else {
			unlink($file . '.webauthn-orig');
		}
	}
	if (webauthn_hook_current($src, $target)) {
		@unlink("/var/run/webauthn_hook_failed_{$target}");
		return true;
	}
	$new = webauthn_hook_apply($src, $target);
	if ($new === null) {
		fwrite(STDERR, "Could not find the hook anchor in {$file}; not patched.\n");
		hook_failed($target, 'hook anchor not found');
		return false;
	}
	if (!webauthn_hook_present($src) && !file_exists(backup_path($file))) {
		@copy($file, backup_path($file));
	}
	if (!replace_file($file, $new)) {
		hook_failed($target, 'write failed');
		return false;
	}
	@unlink("/var/run/webauthn_hook_failed_{$target}");
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

function unpatch_all(): bool {
	$ok = true;
	foreach (webauthn_hook_targets() as $t) {
		$src = @file_get_contents($t['file']);
		if ($src !== false && webauthn_hook_present($src)) {
			$ok = replace_file($t['file'], webauthn_hook_remove($src)) && $ok;
		}
	}
	return $ok;
}

/*
 * Also re-apply the hooks early at boot, before the web GUI starts.
 * rc.bootup runs <earlyshellcmd> even on the first boot after an upgrade
 * or a config restore, when package start scripts are skipped.
 */
function set_earlyshellcmd(bool $present): void {
	$cmds = config_get_path('system/earlyshellcmd', []);
	$cmds = is_array($cmds) ? $cmds : (($cmds === '' || $cmds === null) ? [] : [$cmds]);
	$cmds = array_values(array_filter($cmds, function ($c) {
		return $c !== WEBAUTHN_CRON_COMMAND;
	}));
	if ($present) {
		$cmds[] = WEBAUTHN_CRON_COMMAND;
	}
	if (empty($cmds)) {
		config_del_path('system/earlyshellcmd');
	} else {
		config_set_path('system/earlyshellcmd', $cmds);
	}
}

function earlyshellcmd_present(): bool {
	$cmds = config_get_path('system/earlyshellcmd', []);
	return in_array(WEBAUTHN_CRON_COMMAND, is_array($cmds) ? $cmds : [$cmds], true);
}

/* Re-apply the hooks every 5 minutes; kept in config.xml, so it survives upgrades. */
function set_cron(bool $present): void {
	require_once('services.inc');
	install_cron_job(WEBAUTHN_CRON_COMMAND, $present, '*/5');
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

/* One hook.php at a time: boot, cron and the installer may overlap. */
$lock = @fopen('/var/run/webauthn_hook.lock', 'c');
if ($lock === false || !flock($lock, LOCK_EX)) {
	fwrite(STDERR, "Cannot lock /var/run/webauthn_hook.lock\n");
	exit(1);
}

switch ($argv[1] ?? '') {
case 'install':
	@unlink(WEBAUTHN_UNINSTALLING);
	$ok = patch_all();
	set_earlyshellcmd(true);
	set_menu(true);
	set_cron(true);
	echo $ok ? "WebAuthn hooks installed.\n" : "WebAuthn hooks INCOMPLETE, see errors above.\n";
	exit($ok ? 0 : 1);
case 'uninstall':
	/* Stops an 'ensure' already waiting for the lock from re-patching. */
	touch(WEBAUTHN_UNINSTALLING);
	if (!unpatch_all()) {
		@unlink(WEBAUTHN_UNINSTALLING);
		echo "Could not remove every hook (see errors above); nothing else was changed.\n";
		exit(1);
	}
	set_cron(false);
	set_earlyshellcmd(false);
	set_menu(false);
	echo "WebAuthn hooks removed. Passkeys and settings remain in config.xml.\n";
	break;
case 'ensure':
	if (file_exists(WEBAUTHN_UNINSTALLING)) {
		exit(0);
	}
	exit(patch_all() ? 0 : 1);
case 'status':
	$ok = true;
	foreach (webauthn_hook_targets() as $target => $t) {
		$src = (string)@file_get_contents($t['file']);
		$state = webauthn_hook_current($src, $target) ? 'present' : (webauthn_hook_present($src) ? 'OUTDATED' : 'MISSING');
		$ok = $ok && $state === 'present';
		echo "{$target}: hook {$state}\n";
	}
	$cron = false;
	foreach (config_get_path('cron/item', []) as $item) {
		$cron = $cron || (($item['command'] ?? '') === WEBAUTHN_CRON_COMMAND);
	}
	echo 'cron: re-apply job ' . ($cron ? 'present' : 'MISSING') . "\n";
	$early = earlyshellcmd_present();
	echo 'boot: earlyshellcmd ' . ($early ? 'present' : 'MISSING') . "\n";
	exit($ok && $cron && $early ? 0 : 1);
default:
	fwrite(STDERR, "usage: {$argv[0]} install|uninstall|status|ensure\n");
	exit(2);
}
