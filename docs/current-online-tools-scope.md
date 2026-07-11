# Current online-tools Scope

This document tracks the first compatibility target: replacing the current CryptoJS-backed online-tools crypto layer without adding new behavior first.

## In Scope First

Cipher components:

- AES
- DES
- Triple DES
- RC4
- RC4Drop

Mode components:

- CBC
- CFB
- CTR
- OFB
- ECB

Padding components:

- Pkcs7
- Iso97971
- AnsiX923
- Iso10126
- ZeroPadding
- NoPadding

KDF components:

- PBKDF2
- EvpKDF

Format components:

- Raw bytes
- OpenSSL `Salted__`

Compatibility details:

- Strict unpad validation matching online-tools behavior.
- CryptoJS-compatible OpenSSL salt envelope.
- Text and file chunk flows should be considered before replacing online-tools integration.

## Out of Scope First

- AES-GCM.
- AAD and authentication tag UI.
- New backend selection concepts.
- Global hash/MAC registries.
- Global encoding or random registries.

## Existing Scaffold Status

Implemented enough to test AES, DES, Triple DES, and RC4 against online-tools-compatible vectors:

- `@crypto/core`
- `@crypto/classic`

`@crypto/classic` contains internal modules for the CryptoJS adapter, AES, DES, Triple DES, RC4, RC4Drop, CBC, CFB, CTR, ECB, OFB, NoPadding, Pkcs7, AnsiX923, Iso10126, Iso97971, ZeroPadding, PBKDF2, EvpKDF, and OpenSSL `Salted__` format.

Current working API:

- `registry.encrypt({ cipher, mode, padding, key, iv, plaintext })`
- `registry.decrypt({ cipher, mode, padding, key, iv, ciphertext })`
- `registry.createEncryptor({ cipher, mode, padding, key, iv })`
- `registry.createDecryptor({ cipher, mode, padding, key, iv })`
- `registry.createCipher({ cipher, mode, padding, key, iv })`
- `registry.createPassphraseCipher({ cipher, mode, padding, passphrase, kdf, format })`
- `registry.createPassphraseCipher(...).createEncryptor()` for streaming passphrase encryption
- `registry.createPassphraseCipher(...).createDecryptor()` for streaming passphrase decryption
- `registry.encrypt({ cipher, key, plaintext, ...cipherSpecificOptions })` for stream ciphers
- `registry.decrypt({ cipher, key, ciphertext, ...cipherSpecificOptions })` for stream ciphers
- `process(input)` / `finalize(input?)`

Metadata/component placeholders:

- GCM mode placeholder inside `@crypto/classic`

Missing package scaffolds for first parity:
- None for the current online-tools AES/DES/Triple DES/RC4 surface.
