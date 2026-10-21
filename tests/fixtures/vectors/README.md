# WebAuthn test vectors

`py_webauthn.json` holds real authenticator responses taken from the test suite of [py_webauthn](https://github.com/duo-labs/py_webauthn) (Duo Labs) at commit `c9ba2b7dad6b76bec89e44c76c8ed81fc43287bb`. They were produced by real authenticators and browsers.

| Kind | Algorithm | Source test |
|---|---|---|
| Registration, `none` attestation | ES256 | `test_verify_registration_response.py::test_verifies_none_attestation_response` |
| Registration, `packed` (YubiKey, Firefox) | ES256 | `test_verify_registration_response_packed.py::test_verify_attestation_from_yubikey_firefox` |
| Registration, `packed` | EdDSA (Ed25519) | `test_verify_registration_response_packed.py::test_verify_attestation_with_okp_public_key` |
| Registration, `tpm` (Surface Pro 4, Windows Hello) | RS256 | `test_verify_registration_response_tpm.py::test_verify_attestation_surface_pro_4` |
| Registration, `apple` (passkey) | ES256 | `test_verify_registration_response_apple.py::test_verify_attestation_apple_passkey` |
| Sign-in | ES256 | `test_verify_authentication_response.py::test_verify_authentication_response_with_EC2_public_key` |
| Sign-in | RS256 | `test_verify_authentication_response.py::test_verify_authentication_response_with_RSA_public_key` |
| Sign-in | EdDSA (Ed25519) | `test_verify_authentication_response.py::test_verify_authentication_response_with_OKP_public_key` |

The values are copied unchanged, except that the TPM vectors' standard, padded base64 was rewritten as unpadded base64url (the encoding browsers and this package use). The attestation statements are present but not verified: this package registers with attestation `none`.

Licence: BSD 3-Clause, Copyright (c) 2017-2021 Duo Security, Inc. The full licence text is in [LICENSE.py_webauthn](LICENSE.py_webauthn).
