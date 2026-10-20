<?php
/*
 * hook.inc
 *
 * Insert/remove the WebAuthn gate call in /etc/inc/authgui.inc. The
 * call goes right after the password check (session_auth()), before
 * pfSense evaluates page privileges.
 *
 * Licensed under the Apache License, Version 2.0.
 */

define('WEBAUTHN_HOOK_BEGIN', '/* BEGIN pfSense-webauthn hook */');
define('WEBAUTHN_HOOK_END', '/* END pfSense-webauthn hook */');
define('WEBAUTHN_AUTHGUI', '/etc/inc/authgui.inc');

function webauthn_hook_block(): string {
	return WEBAUTHN_HOOK_BEGIN . "\n" .
	    "if (file_exists('/usr/local/pkg/webauthn/gate.inc')) {\n" .
	    "\trequire_once('/usr/local/pkg/webauthn/gate.inc');\n" .
	    "\twebauthn_gate();\n" .
	    "}\n" .
	    WEBAUTHN_HOOK_END . "\n";
}

function webauthn_hook_present(string $src): bool {
	return str_contains($src, WEBAUTHN_HOOK_BEGIN);
}

/* Returns the patched source, or null if the anchor was not found. */
function webauthn_hook_apply(string $src): ?string {
	if (webauthn_hook_present($src)) {
		return $src;
	}
	$re = '/^if\s*\(\s*!\s*session_auth\(\)\s*\)\s*\{\s*\n\s*display_login_form\(\);\s*\n\s*exit;\s*\n\}[ \t]*\n/m';
	if (preg_match($re, $src, $m, PREG_OFFSET_CAPTURE) !== 1) {
		return null;
	}
	$pos = $m[0][1] + strlen($m[0][0]);
	return substr($src, 0, $pos) . "\n" . webauthn_hook_block() . substr($src, $pos);
}

function webauthn_hook_remove(string $src): string {
	$re = '/\n?' . preg_quote(WEBAUTHN_HOOK_BEGIN, '/') . '.*?' . preg_quote(WEBAUTHN_HOOK_END, '/') . '\n/s';
	return preg_replace($re, '', $src);
}
