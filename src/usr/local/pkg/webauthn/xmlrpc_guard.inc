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
 * That part applies whether or not the second factor is enabled.
 *
 * While it is enabled, XMLRPC is also refused from every host that is
 * neither an XMLRPC peer (the HA partner) nor on a trusted network: its
 * exec_shell/exec_php methods would otherwise give root to anyone on the
 * LAN who knows the admin password, with no passkey.
 *
 * Licensed under the Apache License, Version 2.0.
 */

require_once(__DIR__ . '/webauthn.inc');

/**
 * @param WebAuthnSettings $settings
 * @param WebAuthnSource $source
 */
function webauthn_xmlrpc_refused(array $source, array $settings): bool {
	if ($source['via_proxy'] || $source['proxy_headers']) {
		return true;
	}
	if (empty($settings['enable'])) {
		return false;
	}
	/* A trusted network does not admit the firewall's own addresses (see
	 * webauthn_is_firewall_address()); an XMLRPC peer listed explicitly does. */
	$allowed = webauthn_split_list($settings['xmlrpc_peers'] ?? '');
	if (empty($source['from_firewall'])) {
		$allowed = array_merge($allowed, webauthn_split_list($settings['trusted_networks'] ?? ''));
	}
	return $source['peer'] === '' || !webauthn_ip_in_list($source['peer'], $allowed);
}

function webauthn_xmlrpc_guard(): void {
	$settings = webauthn_settings();
	$source = webauthn_request_source($_SERVER, $settings);
	if (!webauthn_xmlrpc_refused($source, $settings)) {
		return;
	}
	webauthn_log(LOG_WARNING, ($source['via_proxy'] || $source['proxy_headers']) ?
	    'refused XMLRPC request that arrived through a proxy' :
	    'refused XMLRPC request: the source is not an XMLRPC peer or on a trusted network (System > WebAuthn Passkeys > Settings)', $source);
	http_response_code(403);
	header('Content-Type: text/plain');
	echo "XMLRPC is not available from this address.\n";
	exit;
}
