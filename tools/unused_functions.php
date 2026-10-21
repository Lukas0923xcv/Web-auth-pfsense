<?php
/*
 * Fail if a function defined in src/ is never called from src/ (dead
 * code): php tools/unused_functions.php
 * PHPStan (level 6, see phpstan.neon) finds unreachable statements; this
 * finds whole functions nothing uses. Calls from tests do not count.
 */
$root = dirname(__DIR__) . '/src';
$defined = [];
$sources = [];
$it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root));
foreach ($it as $file) {
	if (preg_match('/\.(inc|php)$/', $file->getFilename())) {
		$sources[$file->getPathname()] = file_get_contents($file->getPathname());
	}
}
/* The entry points pfSense or the hooks call. */
$entry = ['webauthn_gate', 'webauthn_cached_privileges_allowed', 'webauthn_xmlrpc_guard'];
foreach ($sources as $src) {
	preg_match_all('/^function\s+(\w+)\s*\(/m', $src, $m);
	foreach ($m[1] as $name) {
		$defined[$name] = true;
	}
}
$unused = [];
foreach (array_keys($defined) as $name) {
	if (in_array($name, $entry, true)) {
		continue;
	}
	$uses = 0;
	foreach ($sources as $src) {
		/* Calls, and names passed as callables ('name'). */
		$uses += preg_match_all('/(?<!function )\b' . preg_quote($name, '/') . '\s*\(|[\'"]' . preg_quote($name, '/') . '[\'"]/', $src);
	}
	if ($uses === 0) {
		$unused[] = $name;
	}
}
foreach ($unused as $name) {
	echo "unused function: $name()\n";
}
echo count($defined) . ' functions, ' . count($unused) . " unused\n";
exit($unused ? 1 : 0);
