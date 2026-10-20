<?php
/*
 * R3: on a full disk, hook.php must leave authgui.inc unchanged. An
 * empty authgui.inc (php -l accepts one) would remove all GUI login.
 *
 * Usage (root, needs a tiny full filesystem; see hook_enospc.sh):
 *   php tests/review3/hook_enospc.php <dir-on-full-fs>
 * The real hook.inc and hook.php functions are loaded with the target
 * path and the php binary path substituted.
 */
$dir = $argv[1];
$repo = dirname(__DIR__, 2);
$pkg = "$repo/src/usr/local/pkg/webauthn";
$target = "$dir/authgui.inc";

$hook = file_get_contents("$pkg/hook.inc");
$hook = str_replace("'/etc/inc/authgui.inc'", var_export($target, true), $hook);
eval('?>' . $hook);

/* hook.php up to its command dispatch, without the pfSense includes. */
$php = file_get_contents("$pkg/hook.php");
$php = substr($php, 0, strpos($php, "\n/* One hook.php at a time"));
$php = preg_replace('/^#!.*\n/', '', $php);
$php = preg_replace('/^require_once\(.*\);\n/m', '', $php);
eval('?>' . str_replace('/usr/local/bin/php', PHP_BINARY, $php));

$before = file_get_contents($target);
$ok = patch_target('authgui');
clearstatcache();
$after = file_get_contents($target);
@unlink('/var/run/webauthn_hook_failed_authgui');
echo 'patch_target returned ' . var_export($ok, true) . '; authgui.inc ' . strlen($before) . ' -> ' . strlen($after) . " bytes\n";
$leftover = glob("$dir/authgui.inc.webauthn-tmp-*");
$good = !$ok && $after === $before && empty($leftover);
echo $good ? "ok: patch refused, authgui.inc unchanged, no temp file left\n"
    : "FAIL: authgui.inc changed or patch reported success on a full disk\n";
exit($good ? 0 : 1);
