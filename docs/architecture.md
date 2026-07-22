# Architecture

`@jscrypto/core` defines the framework contract. It intentionally does not implement AES, CBC, PBKDF2, OpenSSL formatting, or backend selection.

First-class component kinds:

- `cipher`
- `mode`
- `padding`
- `kdf`
- `hash`
- `format`
- `preset`

KDF components resolve hash implementations through the core registry. Applications register a
`HashComponent` with `registry.useHash(hash)` and KDFs access it through their derive context.
Hash names are normalized, so `sha-256`, `SHA256`, and `sha256` address the same component.
CryptoJS-compatible `SHA3` is Keccak-512; the classic hashes entry registers `KECCAK512` as the
accurate name and keeps `SHA3` as a deprecated compatibility alias.

## Non-goals for core

- No global backend registry. A package can choose its own implementation dependency.
- No encoding registry in the first version.
- No random source registry in the first version.
- No CryptoJS `WordArray` in the core data model.

## Data Model

Core APIs are `Uint8Array`-first. String encodings, CryptoJS adapters, and OpenSSL-compatible packaging belong in helper or format packages.

## Package Surface

The public npm surface is currently two packages plus one opt-in subpath:

- `@jscrypto/core`: framework contracts and shared helpers.
- `@jscrypto/classic`: classic ciphers, modes, paddings, KDFs, and formats with CryptoJS-compatible outputs where compatibility is intentional.
- `@jscrypto/classic/hashes`: opt-in CryptoJS-compatible hash components for KDF/derived-key use.

Inside `@jscrypto/classic`, code remains split by concern under `src/ciphers`, `src/modes`, `src/paddings`, `src/kdfs`, `src/formats`, `src/hashes`, and `src/preset`. Concrete hashes are deliberately excluded from the main classic entry and browser bundle; consumers opt in through the hashes subpath and call `registerClassicHashes(registry)`.

Mode components provide stateful transform factories only. One-shot encryption and decryption are registry conveniences built by creating a transform and finalizing it with the complete input.

Cipher components are split by `type`:

- `block`: exposes `create(key).encryptBlock/decryptBlock` and is composed with mode and padding components.
- `stream`: exposes `createEncryptor/createDecryptor` directly and does not use mode, padding, or IV.

## Implementation Order

The first milestone is a standalone classic compatibility package with AES-GCM and no CryptoJS runtime dependency.

Initial parity modules inside `@jscrypto/classic`:

- AES, DES, Triple DES
- RC4, RC4Drop
- CBC, CFB, CTR, OFB, ECB, GCM
- Pkcs7, Iso97971, AnsiX923, Iso10126, ZeroPadding, NoPadding
- PBKDF2, EvpKDF (with hashes registered explicitly)
- OpenSSL `Salted__` format
- Opt-in `@jscrypto/classic/hashes`

Deferred modules:

- Higher-level passphrase plus nonce flows for AEAD modes
- Additional AEAD-specific API helpers
