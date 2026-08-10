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
- `aead`

KDF components resolve hash implementations through the core registry. Applications register a
`HashComponent` with `registry.useHash(hash)` and KDFs access it through their derive context.
Hash names are normalized, so `sha-256`, `SHA256`, and `sha256` address the same component.
CryptoJS-compatible `SHA3` is Keccak-512; the classic hashes entry registers it as `KECCAK512`.

## Non-goals for core

- No global backend registry. A package can choose its own implementation dependency.
- No encoding registry in the first version.
- No random source registry in the first version.
- No CryptoJS `WordArray` in the core data model.

## Data Model

Core APIs are `Uint8Array`-first. String encodings, CryptoJS adapters, and OpenSSL-compatible packaging belong in helper or format packages.

## Package Surface

The public npm surface is split by component type:

- `@jscrypto/core`: framework contracts and shared helpers.
- `@jscrypto/ciphers`: AES, DES, Triple DES, RC4, RC4Drop, SPECK, ChaCha20, XChaCha20, plus AEAD components AES-GCM, ChaCha20-Poly1305, and XChaCha20-Poly1305.
- `@jscrypto/modes`: CBC, CFB, CTR, ECB, OFB, and compatibility GCM mode.
- `@jscrypto/paddings`: classic block padding components plus compatibility aliases such as Pkcs5.
- `@jscrypto/kdfs`: PBKDF2, EvpKDF, HKDF, HKDF-Extract, HKDF-Expand, Scrypt, and Argon2.
- `@jscrypto/formats`: OpenSSL `Salted__` formatting.
- `@jscrypto/hashes`: opt-in hash components for KDF/derived-key use.
- `@jscrypto/suite`: ready-to-use basic and all registries that combine official components.

Component packages expose both package-level presets and subpath exports such as `@jscrypto/ciphers/aes`, `@jscrypto/modes/cbc`, and `@jscrypto/paddings/pkcs7`. Browser bundles remain split by package, while `@jscrypto/suite` provides a convenient bundle for applications that want the official set at once.

Mode components provide stateful transform factories only. One-shot encryption and decryption are registry conveniences built by creating a transform and finalizing it with the complete input.

Cipher facades accept per-operation material at `encrypt`, `decrypt`, `createEncryptor`, and `createDecryptor` time. Core forwards these options to mode and cipher components without encoding mode-specific parameter names. `mutableInput: true` is a best-effort transform hint: modes may reuse or mutate the input buffer when safe, and may ignore the hint for formats, padding, AEAD, or other flows that need distinct buffers. For derived-key ciphers the KDF `salt` is also an operation option. Core passes salt when available; each KDF validates or defaults its own salt behavior. Modes define any derived IV material length through `ModeComponent.getIvSize(...)`; compatibility GCM mode returns 0 and requires a per-operation nonce instead. Formats serialize or parse metadata such as salt; they do not generate random salt in the derived-key API.

Prefer `registry.createAead({ algorithm, key })` for authenticated encryption.
AEAD components expose one-shot `seal` / `open` rather than streaming
`process` / `finalize`. `seal()` appends the authentication tag;
`open()` accepts appended or detached tags. AEAD has no padding.

`@jscrypto/core` exports `randomBytes(length)` for caller-owned salt, IV, and nonce material. Operation options must not override reserved facade keys such as `cipher`, `mode`, `padding`, `key`, `algorithm`, `kdf`, or `format`.

Cipher components are split by `type`:

- `block`: exposes `create(key).encrypt(input, output)` and `decrypt(input, output)` for raw block-multiple input and caller-owned output buffers.
- `stream`: exposes `createEncryptor/createDecryptor` directly and does not use mode, padding, or IV.

AEAD components are selected by full algorithm name such as `AES-GCM` or
`ChaCha20-Poly1305`, not by `cipher` + `mode`.

## Implementation Order

The first milestone was a standalone compatibility package with AES-GCM and no CryptoJS runtime dependency. The current milestone uses component packages plus `@jscrypto/suite`; `@jscrypto/classic` was removed in v0.10.0.

Initial parity and extension modules now live in component packages:

- AES, DES, Triple DES
- RC4, RC4Drop
- SPECK
- ChaCha20, XChaCha20
- AES-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305 AEAD components
- CBC, CFB, CTR, OFB, ECB, compatibility GCM mode
- Pkcs7, Pkcs5, Iso97971, AnsiX923, Iso10126, ZeroPadding, NoPadding
- PBKDF2, EvpKDF (with hashes registered explicitly)
- HKDF, HKDF-Extract, HKDF-Expand
- Scrypt, Argon2
- OpenSSL `Salted__` format
- `@jscrypto/hashes`

Deferred modules:

- Higher-level passphrase plus nonce flows for AEAD
- Streaming or chunked AEAD framing helpers
- Additional AEAD algorithms such as AES-CCM or AES-SIV
