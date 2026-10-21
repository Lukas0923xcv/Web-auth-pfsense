<?php
/*
 * List functions longer than the limit (default 80 lines) in the package:
 *   php tools/function_lengths.php [limit]
 * A function may be longer only if the comment right above it has a line
 * starting with "Long:" that says why. Exits 1 if one is too long without.
 */
$limit = (int)($argv[1] ?? 80);
$root = dirname(__DIR__) . '/src';
$bad = 0;
$it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root));
foreach ($it as $file) {
	if (!preg_match('/\.(inc|php)$/', $file->getFilename())) {
		continue;
	}
	$tokens = token_get_all(file_get_contents($file->getPathname()));
	$comment = '';
	for ($i = 0; $i < count($tokens); $i++) {
		$t = $tokens[$i];
		if (is_array($t) && in_array($t[0], [T_COMMENT, T_DOC_COMMENT], true)) {
			$comment = $t[1];
			continue;
		}
		if (!is_array($t) || $t[0] !== T_FUNCTION) {
			if (!(is_array($t) && $t[0] === T_WHITESPACE)) {
				$comment = '';
			}
			continue;
		}
		/* Named functions only: "function" followed by a name. */
		$j = $i + 1;
		while (is_array($tokens[$j]) && $tokens[$j][0] === T_WHITESPACE) {
			$j++;
		}
		if (!is_array($tokens[$j]) || $tokens[$j][0] !== T_STRING) {
			continue;
		}
		$name = $tokens[$j][1];
		$start = $t[2];
		$depth = 0;
		$end = $start;
		for ($k = $j; $k < count($tokens); $k++) {
			$x = $tokens[$k];
			if ($x === '{' || (is_array($x) && in_array($x[0], [T_CURLY_OPEN, T_DOLLAR_OPEN_CURLY_BRACES], true))) {
				$depth++;
			} elseif ($x === '}') {
				$depth--;
				if ($depth === 0) {
					break;
				}
			}
			if (is_array($x)) {
				$end = $x[2] + substr_count($x[1], "\n");
			}
		}
		$len = $end - $start + 1;
		$why = preg_match('/^\s*\*?\s*Long:/m', $comment) === 1;
		if ($len > $limit) {
			printf("%s %s(): %d lines%s\n", substr($file->getPathname(), strlen($root) + 1), $name, $len, $why ? ' (reason given)' : ' TOO LONG');
			$bad += $why ? 0 : 1;
		}
		$comment = '';
	}
}
exit($bad ? 1 : 0);
