<?php
/*
 * xmlrpc_guard.inc
 *
 * XMLRPC (HA sync) authenticates with a password over HTTP basic auth and
 * never passes the WebAuthn gate. Refuse it whenever the request came
 * through cloudflared or any other reverse proxy; legitimate HA peers
 * connect directly. Path tricks such as //xmlrpc.php can slip past an
 * anchored path rule on the tunnel, so this check runs in pfSense itself.
 *
 * Applies whether or not the second factor is enabled.
 *
 * Licensed under the Apache License, Version 2.0.
 */

require_once(__DIR__ . '/webauthn.inc');

function webauthn_xmlrpc_refused(array $source): bool {
	return $source['via_proxy'] || $source['proxy_headers'];
}

function webauthn_xmlrpc_guard(): void {
	$source = webauthn_request_source($_SERVER, webauthn_settings());
	if (!webauthn_xmlrpc_refused($source)) {
		return;
	}
	webauthn_log(LOG_WARNING, 'refused XMLRPC request that arrived through a proxy', $source);
	http_response_code(403);
	header('Content-Type: text/plain');
	echo "XMLRPC is not available through a proxy.\n";
	exit;
}
