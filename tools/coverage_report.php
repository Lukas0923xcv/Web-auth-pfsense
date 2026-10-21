<?php
/*
 * Merge the per-process coverage files written by
 * tests/support/coverage_prepend.php and print a Markdown table of line
 * coverage per file. Exits 1 if a file in the required set is below the
 * minimum. Usage: php tools/coverage_report.php <coverage dir>
 */
const REQUIRED = [
	'usr/local/pkg/webauthn/webauthn_lib.inc',
	'usr/local/pkg/webauthn/cbor.inc',
	'usr/local/pkg/webauthn/gate.inc',
	'usr/local/pkg/webauthn/challenge.inc',
	'usr/local/pkg/webauthn/storage.inc',
];
const MINIMUM = 85.0;

$dir = $argv[1] ?? '';
$runs = glob("$dir/*.json") ?: [];
if (empty($runs)) {
	fwrite(STDERR, "No coverage data in '$dir' (is pcov loaded?)\n");
	exit(1);
}
/* file => line => executed? A line counts as run if any process ran it. */
$merged = [];
foreach ($runs as $f) {
	foreach ((array)json_decode((string)file_get_contents($f), true) as $file => $lines) {
		foreach ($lines as $line => $hits) {
			$merged[$file][$line] = ($merged[$file][$line] ?? false) || $hits > 0;
		}
	}
}
ksort($merged);
$ok = true;
echo "| File | Lines | Covered | Coverage | Required |\n|---|---:|---:|---:|---|\n";
foreach ($merged as $file => $lines) {
	$total = count($lines);
	$hit = count(array_filter($lines));
	$pct = $total ? 100 * $hit / $total : 100;
	$req = in_array($file, REQUIRED, true);
	$pass = !$req || $pct >= MINIMUM;
	$ok = $ok && $pass;
	printf("| %s | %d | %d | %.1f%% | %s |\n", $file, $total, $hit, $pct, $req ? ($pass ? '>= ' . MINIMUM . '% ok' : '**below ' . MINIMUM . '%**') : '');
}
foreach (REQUIRED as $file) {
	if (!isset($merged[$file])) {
		echo "| $file | - | - | not loaded | **missing** |\n";
		$ok = false;
	}
}
exit($ok ? 0 : 1);
