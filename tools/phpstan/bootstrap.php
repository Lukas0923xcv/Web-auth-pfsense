<?php
/* pfSense finds its own includes (config.inc, guiconfig.inc, ...) through
 * the include path; point PHPStan at empty placeholders for them. */
set_include_path(__DIR__ . '/pfsense' . PATH_SEPARATOR . get_include_path());
