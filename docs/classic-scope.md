# Classic Package Scope

This document tracks the current `@jscrypto/classic` package scope. The package is intended to stand on its own as a classic cryptography component set, with CryptoJS-compatible outputs where compatibility is intentional.

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
- GCM

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

- Strict unpad validation.
- CryptoJS-compatible OpenSSL salt envelope.
- KDF hashes are registry components. `@jscrypto/classic` does not register or bundle them by
  default; consumers can call `registerClassicHashes(registry)` from
  `@jscrypto/classic/hashes`, or register a custom `HashComponent` with `registry.useHash(...)`.
- CryptoJS-compatible `SHA3` is Keccak-512. `@jscrypto/classic/hashes` registers `KECCAK512`
  as the accurate name and keeps `SHA3` as a deprecated compatibility alias.
- Text and file chunk flows should be supported through the streaming transform APIs.

## Out of Scope First

- automatic passphrase/KDF nonce generation for AES-GCM.
- New backend selection concepts.
- Global encoding or random registries.

## Current Status

Implemented as standalone packages:

- `@jscrypto/core`
- `@jscrypto/classic`

`@jscrypto/classic` contains internal modules for AES, DES, Triple DES, RC4, RC4Drop, CBC, CFB, CTR, ECB, OFB, GCM, NoPadding, Pkcs7, AnsiX923, Iso10126, Iso97971, ZeroPadding, PBKDF2, EvpKDF, and OpenSSL `Salted__` format. The optional `@jscrypto/classic/hashes` entry provides MD5, SHA-1/2, KECCAK512, deprecated SHA3 compatibility alias, and RIPEMD160 components without adding them to the main classic entry. RIPEMD160 is implemented locally, and `@jscrypto/classic` no longer depends on CryptoJS.

Current working API:

- `registry.encrypt({ cipher, mode, padding, key, iv, plaintext })`
- `registry.decrypt({ cipher, mode, padding, key, iv, ciphertext })`
- `registry.createEncryptor({ cipher, mode, padding, key, iv })`
- `registry.createDecryptor({ cipher, mode, padding, key, iv })`
- `registry.createCipher({ cipher, mode, padding, key, iv })`
- `registry.createDerivedKeyCipher({ cipher, mode, padding, kdf, format })`
- `registry.derive({ name, input, length, ...kdfParams })`
- `registry.createPassphraseCipher({ cipher, mode, padding, passphrase, kdf, format })` (deprecated compatibility alias)
- `registry.createDerivedKeyCipher(...).createEncryptor()` for streaming derived-key encryption
- `registry.createDerivedKeyCipher(...).createDecryptor()` for streaming derived-key decryption
- `registry.useHash(hash)` / `registry.getHash(name)` for KDF hash registration and lookup
- `registry.encrypt({ cipher, key, plaintext, ...cipherSpecificOptions })` for stream ciphers
- `registry.decrypt({ cipher, key, ciphertext, ...cipherSpecificOptions })` for stream ciphers
- `process(input)` / `finalize(input?)`

Metadata/component placeholders:

- None for the current AES/DES/Triple DES/RC4/AES-GCM surface.

Missing package scaffolds for first parity:
- None for the current AES/DES/Triple DES/RC4 surface.
