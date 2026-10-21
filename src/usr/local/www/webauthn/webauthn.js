/*
 * webauthn.js
 *
 * Browser side of the pfSense WebAuthn second factor. The ceremonies
 * fill hidden fields and submit an ordinary form so pfSense's CSRF
 * protection (csrf-magic) applies as it does to any other GUI form.
 *
 * Licensed under the Apache License, Version 2.0.
 */

function webauthnB64urlToBuf(s) {
	s = s.replace(/-/g, '+').replace(/_/g, '/');
	while (s.length % 4) {
		s += '=';
	}
	var bin = atob(s);
	var buf = new Uint8Array(bin.length);
	for (var i = 0; i < bin.length; i++) {
		buf[i] = bin.charCodeAt(i);
	}
	return buf.buffer;
}

function webauthnBufToB64url(buf) {
	var bytes = new Uint8Array(buf);
	var bin = '';
	for (var i = 0; i < bytes.length; i++) {
		bin += String.fromCharCode(bytes[i]);
	}
	return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function webauthnSetError(msg) {
	var el = document.getElementById('webauthn-error');
	if (el) {
		el.textContent = msg;
	} else {
		alert(msg);
	}
}

function webauthnSupported() {
	if (!window.isSecureContext || !window.PublicKeyCredential || !navigator.credentials) {
		webauthnSetError('This browser or connection does not support passkeys (an HTTPS hostname is required).');
		return false;
	}
	return true;
}

/*
 * Is the page on one of the allowed origins? If not, show the
 * "wrong hostname" message instead of starting a ceremony that the
 * browser or the server would reject.
 */
function webauthnCheckOrigin(opts, hideId) {
	var here = window.location.origin.toLowerCase();
	var ok = (opts.origins || []).some(function (o) {
		return o.toLowerCase().replace(/\/+$/, '') === here;
	});
	if (!ok) {
		var msg = document.getElementById('webauthn-wronghost');
		if (msg) {
			msg.style.display = '';
		}
		var hide = document.getElementById(hideId);
		if (hide) {
			hide.style.display = 'none';
		}
	}
	return ok;
}

function webauthnLoginInit() {
	var btn = document.getElementById('webauthn-go');
	if (!btn) {
		return;
	}
	var opts = JSON.parse(btn.getAttribute('data-options'));
	if (!webauthnCheckOrigin(opts, 'webauthn-ready')) {
		return;
	}
	var run = function () {
		if (!webauthnSupported()) {
			return;
		}
		var publicKey = {
			challenge: webauthnB64urlToBuf(opts.challenge),
			rpId: opts.rpId,
			timeout: opts.timeout,
			userVerification: opts.userVerification,
			allowCredentials: opts.allowCredentials.map(function (c) {
				return {type: c.type, id: webauthnB64urlToBuf(c.id)};
			})
		};
		btn.disabled = true;
		navigator.credentials.get({publicKey: publicKey}).then(function (cred) {
			document.getElementById('credential_id').value = webauthnBufToB64url(cred.rawId);
			document.getElementById('client_data').value = webauthnBufToB64url(cred.response.clientDataJSON);
			document.getElementById('authenticator_data').value = webauthnBufToB64url(cred.response.authenticatorData);
			document.getElementById('signature').value = webauthnBufToB64url(cred.response.signature);
			if (cred.response.userHandle) {
				document.getElementById('user_handle').value = webauthnBufToB64url(cred.response.userHandle);
			}
			document.getElementById('webauthn-form').submit();
		}).catch(function (e) {
			btn.disabled = false;
			webauthnSetError('Passkey request failed or was cancelled (' + e.name + ').');
		});
	};
	btn.addEventListener('click', run);
	/* Start right away; browsers that need a user gesture will reject and
	 * the button remains available. */
	run();
}

function webauthnRegisterInit() {
	var btn = document.getElementById('webauthn-register');
	if (!btn) {
		return;
	}
	if (!webauthnCheckOrigin(JSON.parse(btn.getAttribute('data-options')), 'webauthn-register-form')) {
		return;
	}
	btn.addEventListener('click', function () {
		if (!webauthnSupported()) {
			return;
		}
		var name = document.getElementById('passkey_name');
		if (name && !name.value.trim()) {
			webauthnSetError('Enter a name for the passkey first.');
			name.focus();
			return;
		}
		var opts = JSON.parse(btn.getAttribute('data-options'));
		var publicKey = {
			challenge: webauthnB64urlToBuf(opts.challenge),
			rp: opts.rp,
			user: {
				id: webauthnB64urlToBuf(opts.user.id),
				name: opts.user.name,
				displayName: opts.user.displayName
			},
			pubKeyCredParams: opts.algs.map(function (a) {
				return {type: 'public-key', alg: a};
			}),
			timeout: opts.timeout,
			attestation: 'none',
			authenticatorSelection: {
				residentKey: 'preferred',
				userVerification: opts.userVerification
			},
			excludeCredentials: opts.exclude.map(function (id) {
				return {type: 'public-key', id: webauthnB64urlToBuf(id)};
			})
		};
		btn.disabled = true;
		navigator.credentials.create({publicKey: publicKey}).then(function (cred) {
			document.getElementById('reg_client_data').value = webauthnBufToB64url(cred.response.clientDataJSON);
			document.getElementById('reg_attestation').value = webauthnBufToB64url(cred.response.attestationObject);
			document.getElementById('webauthn-register-form').submit();
		}).catch(function (e) {
			btn.disabled = false;
			webauthnSetError('Passkey registration failed or was cancelled (' + e.name + ').');
		});
	});
}
