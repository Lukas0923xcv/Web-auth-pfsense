<?php
/*
 * Check that every WebAuthn hook applies to a copy of pfSense's files:
 *   php tools/check_anchors.php <dir with authgui.inc, auth_check.inc, xmlrpc.php>
 * For each file: the hook anchor is found, the patched file passes
 * `php -l`, and removing the hook gives back the original byte for byte.
 * Exits 1 if any check fails.
 */
require_once(dirname(__DIR__) . '/src/usr/local/pkg/webauthn/hook.inc');

$dir = $argv[1] ?? '';
$ok = true;
foreach (webauthn_hook_targets() as $target => $t) {
	$file = $dir . '/' . basename($t['file']);
	$src = @file_get_contents($file);
	if ($src === false) {
		echo "$target: cannot read $file\n";
		$ok = false;
		continue;
	}
	$patched = webauthn_hook_apply($src, $target);
	if ($patched === null) {
		echo "$target: hook anchor NOT FOUND in $file\n";
		$ok = false;
		continue;
	}
	$tmp = tempnam(sys_get_temp_dir(), 'anchor');
	file_put_contents($tmp, $patched);
	exec(escapeshellarg(PHP_BINARY) . ' -l ' . escapeshellarg($tmp) . ' 2>&1', $out, $rc);
	unlink($tmp);
	if ($rc !== 0) {
		echo "$target: patched $file fails php -l:\n" . implode("\n", $out) . "\n";
		$ok = false;
		continue;
	}
	if (webauthn_hook_remove($patched) !== $src) {
		echo "$target: removing the hook does not restore $file\n";
		$ok = false;
		continue;
	}
	echo "$target: ok (" . basename($file) . ', sha256 ' . substr(hash('sha256', $src), 0, 16) . ")\n";
}
exit($ok ? 0 : 1);
