<?php
/* One "request" of system_webauthn.php act=delete by a non-admin with a password-only session. Usage: race_delete.php <id> <start> */
require __DIR__ . '/race_stub.inc';
[, $id, $start] = $argv;
while (microtime(true) < (float)$start) {
}
$ok = webauthn_delete_credential($id, 'bob', false, $err);
echo $ok ? "deleted\n" : "refused: $err\n";
