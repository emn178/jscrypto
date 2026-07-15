# Change Log

## v0.3.0 / 2026-07-15

### Added

- added opt-in `@jscrypto/classic/hashes` with `registerClassicHashes(registry)` and a separate hashes browser bundle.
- added core `hash` component kind with `registry.useHash(...)` / `registry.getHash(...)` for KDF hash lookup.
- added native AES, DES, Triple DES, EvpKDF, PBKDF2, and CryptoJS-compatible hash implementations.

### Changed

- KDF components resolve hashes through a derive context instead of an implicit CryptoJS hasher lookup.
- direct helpers `deriveEvpKdf` / `derivePbkdf2` now require a concrete `HashComponent`.
- removed deprecated TypeScript `baseUrl` / `paths` from shared tsconfig in favor of package exports and workspaces.

### Removed

- removed the `crypto-js` runtime dependency from `@jscrypto/classic`.
- removed `@types/crypto-js`.
- removed the public CryptoJS adapter export (`CryptoJS`, WordArray helpers, and related APIs).

## v0.2.0 / 2026-07-12

### Added

- added AES-GCM mode with AAD, nonce alias, detached tag support, configurable tag length, and streaming encryption/decryption transforms.
- added NIST AES-GCM vectors and authentication failure coverage.

### Changed

- allowed block modes with `requiresPadding: false` to be used without a padding component.
- passed transform options through to block mode components so AEAD modes can read mode-specific options.

## v0.1.0 / 2026-07-11

### Added

- created `@jscrypto/core` with registry, component contracts, byte helpers, block helpers, cipher facade, and passphrase cipher facade.
- created `@jscrypto/classic` with AES, DES, Triple DES, RC4, RC4Drop, CBC, CFB, CTR, OFB, ECB, classic paddings, PBKDF2, EvpKDF, and OpenSSL `Salted__` format.
- added one-shot and streaming encryption/decryption APIs.
- added ESM, CommonJS, IIFE, and UMD builds for browser and Node.js usage.
