<?php
/*
 * hook.inc
 *
 * Insert/remove the WebAuthn hooks in pfSense files:
 *
 *   authgui     /etc/inc/authgui.inc: run the gate right after the
 *               password check (session_auth()), before pfSense
 *               evaluates page privileges.
 *   auth_check  /etc/inc/auth_check.inc: the lightweight check used by
 *               getstats.php, ifstats.php etc. trusts the session's cached
 *               page privileges; ignore them unless the session has passed
 *               the gate, so the request falls through to authgui.inc.
 *   xmlrpc      /usr/local/www/xmlrpc.php: refuse XMLRPC (password-only
 *               HTTP basic auth) when it arrives through a proxy.
 *
 * The hooks require their files unconditionally: if the package files
 * are missing, the GUI fails closed instead of skipping the check.
 *
 * Licensed under the Apache License, Version 2.0.
 */

define('WEBAUTHN_HOOK_BEGIN', '/* BEGIN pfSense-webauthn hook */');
define('WEBAUTHN_HOOK_END', '/* END pfSense-webauthn hook */');
define('WEBAUTHN_AUTHGUI', '/etc/inc/authgui.inc');

function webauthn_hook_targets(): array {
	return [
		'authgui' => [
			'file' => WEBAUTHN_AUTHGUI,
			'anchor' => '/^if\s*\(\s*!\s*session_auth\(\)\s*\)\s*\{\s*\n\s*display_login_form\(\);\s*\n\s*exit;\s*\n\}[ \t]*\n/m',
			'body' => "require_once('/usr/local/pkg/webauthn/gate.inc');\n" .
			    "webauthn_gate();\n",
		],
		'auth_check' => [
			'file' => '/etc/inc/auth_check.inc',
			'anchor' => '/^\$session_pagematch\s*=\s*session_read_single_var\(\s*["\']page-match["\']\s*\);[ \t]*\n/m',
			'body' => "require_once('config.inc');\n" .
			    "require_once('/usr/local/pkg/webauthn/gate.inc');\n" .
			    "if (!webauthn_cached_privileges_allowed()) {\n" .
			    "\t\$session_pagematch = null;\n" .
			    "}\n",
		],
		'xmlrpc' => [
			'file' => '/usr/local/www/xmlrpc.php',
			'anchor' => '/^require_once\(\s*["\']config\.inc["\']\s*\);[ \t]*\n/m',
			'body' => "require_once('/usr/local/pkg/webauthn/xmlrpc_guard.inc');\n" .
			    "webauthn_xmlrpc_guard();\n",
		],
	];
}

function webauthn_hook_block(string $target = 'authgui'): string {
	return WEBAUTHN_HOOK_BEGIN . "\n" . webauthn_hook_targets()[$target]['body'] . WEBAUTHN_HOOK_END . "\n";
}

function webauthn_hook_present(string $src): bool {
	return str_contains($src, WEBAUTHN_HOOK_BEGIN);
}

/* Is the current version of the hook in place? */
function webauthn_hook_current(string $src, string $target = 'authgui'): bool {
	return str_contains($src, webauthn_hook_block($target));
}

function webauthn_hook_remove(string $src): string {
	$re = '/\n?' . preg_quote(WEBAUTHN_HOOK_BEGIN, '/') . '.*?' . preg_quote(WEBAUTHN_HOOK_END, '/') . '\n/s';
	return preg_replace($re, '', $src);
}

/*
 * Returns the source with the current hook in place (replacing any older
 * version), or null if the anchor was not found.
 */
function webauthn_hook_apply(string $src, string $target = 'authgui'): ?string {
	$clean = webauthn_hook_remove($src);
	if (preg_match(webauthn_hook_targets()[$target]['anchor'], $clean, $m, PREG_OFFSET_CAPTURE) !== 1) {
		return null;
	}
	$pos = $m[0][1] + strlen($m[0][0]);
	return substr($clean, 0, $pos) . "\n" . webauthn_hook_block($target) . substr($clean, $pos);
}
