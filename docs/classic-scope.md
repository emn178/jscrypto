# Classic Package Scope

This document tracks the compatibility scope of `@jscrypto/classic`. The package now aggregates the component packages while preserving the original classic API surface.

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
- KDF hashes are registry components. `@jscrypto/classic` does not register them by
  default; consumers can call `registry.use(hashesPreset)` from `@jscrypto/hashes`,
  `registry.use(classicHashesPreset)` from `@jscrypto/classic/hashes`, or register a
  custom `HashComponent` with `registry.useHash(...)`.
- CryptoJS-compatible `SHA3` is Keccak-512. `@jscrypto/hashes` registers it as
  `KECCAK512`.
- Text and file chunk flows should be supported through the streaming transform APIs.

## Out of Scope First

- automatic passphrase/KDF nonce generation for AES-GCM.
- New backend selection concepts.
- Global encoding or random registries.

## Current Status

Implemented as component packages:

- `@jscrypto/core`
- `@jscrypto/ciphers`
- `@jscrypto/modes`
- `@jscrypto/paddings`
- `@jscrypto/kdfs`
- `@jscrypto/formats`
- `@jscrypto/hashes`
- `@jscrypto/suite`

`@jscrypto/classic` is a compatibility aggregate, not the place for new algorithms. SPECK and ChaCha20 live in `@jscrypto/ciphers`; HKDF lives in `@jscrypto/kdfs`; `@jscrypto/suite/all` combines them with the classic compatibility set.

`@jscrypto/classic` re-exports AES, DES, Triple DES, RC4, RC4Drop, CBC, CFB, CTR, ECB, OFB, GCM, NoPadding, Pkcs7, AnsiX923, Iso10126, Iso97971, ZeroPadding, PBKDF2, EvpKDF, and OpenSSL `Salted__` format from the component packages. The optional `@jscrypto/classic/hashes` entry re-exports `@jscrypto/hashes` for compatibility. RIPEMD160 is implemented locally, and `@jscrypto/classic` no longer depends on CryptoJS.

Current working API:

- `registry.encrypt({ cipher, mode, padding, key, iv, plaintext })`
- `registry.decrypt({ cipher, mode, padding, key, iv, ciphertext })`
- `registry.createEncryptor({ cipher, mode, padding, key, iv })`
- `registry.createDecryptor({ cipher, mode, padding, key, iv })`
- `registry.createCipher({ cipher, mode, padding, key, iv })`
- `registry.createDerivedKeyCipher({ cipher, mode, padding, kdf, format })`
- `registry.derive({ name, input, length, ...kdfParams })`
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
