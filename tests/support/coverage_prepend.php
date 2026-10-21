<?php
/*
 * Loaded before every test process (also the ones tests start themselves)
 * when tests/run_all.sh runs with COVERAGE=1: records which lines of src/
 * ran, one JSON file per process in $WEBAUTHN_COVERAGE_DIR.
 * tools/coverage_report.php merges them.
 */
if (extension_loaded('pcov') && getenv('WEBAUTHN_COVERAGE_DIR')) {
	\pcov\start();
	register_shutdown_function(function () {
		\pcov\stop();
		$src = dirname(__DIR__, 2) . '/src/';
		$out = [];
		foreach (\pcov\collect(\pcov\all) as $file => $lines) {
			if (str_starts_with($file, $src)) {
				$out[substr($file, strlen($src))] = $lines;
			}
		}
		@file_put_contents(getenv('WEBAUTHN_COVERAGE_DIR') . '/' . getmypid() . '-' . bin2hex(random_bytes(4)) . '.json', json_encode($out));
	});
}
