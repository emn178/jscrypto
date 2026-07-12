# Architecture

`@jscrypto/core` defines the framework contract. It intentionally does not implement AES, CBC, PBKDF2, OpenSSL formatting, or backend selection.

First-class component kinds:

- `cipher`
- `mode`
- `padding`
- `kdf`
- `format`
- `preset`

Component modules may expose their own internal extension points. For example, the PBKDF2 implementation in `@jscrypto/classic` may decide how selectable hash functions work without requiring a global hash registry in core.

## Non-goals for core

- No global backend registry. A package can choose its own implementation dependency.
- No global hash/MAC registry in the first version.
- No encoding registry in the first version.
- No random source registry in the first version.
- No CryptoJS `WordArray` in the core data model.

## Data Model

Core APIs are `Uint8Array`-first. String encodings, CryptoJS adapters, and OpenSSL-compatible packaging belong in helper or format packages.

## Compatibility

Compatibility with online-tools should be provided through packages such as:

- `@jscrypto/classic`

The public npm surface is currently two packages:

- `@jscrypto/core`: framework contracts and shared helpers.
- `@jscrypto/classic`: online-tools-compatible classic ciphers, modes, paddings, KDFs, formats, and the CryptoJS adapter used by those implementations.

Inside `@jscrypto/classic`, code remains split by concern under `src/ciphers`, `src/modes`, `src/paddings`, `src/kdfs`, `src/formats`, `src/adapter`, and `src/preset`. That keeps the implementation modular without forcing users to install a separate npm package for every single component.

Mode components provide stateful transform factories only. One-shot encryption and decryption are registry conveniences built by creating a transform and finalizing it with the complete input.

Cipher components are split by `type`:

- `block`: exposes `create(key).encryptBlock/decryptBlock` and is composed with mode and padding components.
- `stream`: exposes `createEncryptor/createDecryptor` directly and does not use mode, padding, or IV.

## Implementation Order

The first milestone is parity with the current CryptoJS-backed online-tools behavior plus AES-GCM.

Initial parity modules inside `@jscrypto/classic`:

- CryptoJS adapter
- AES, DES, Triple DES
- RC4, RC4Drop
- CBC, CFB, CTR, OFB, ECB, GCM
- Pkcs7, Iso97971, AnsiX923, Iso10126, ZeroPadding, NoPadding
- PBKDF2, EvpKDF
- OpenSSL `Salted__` format

Deferred modules:

- Higher-level passphrase plus nonce flows for AEAD modes
- Additional AEAD-specific API helpers
