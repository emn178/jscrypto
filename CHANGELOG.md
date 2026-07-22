# Change Log

## v0.5.0 / 2026-07-22

### Added

- added `registry.derive(...)` for direct KDF invocation.
- added `registry.createDerivedKeyCipher(...)` as the general derived-key cipher facade.

### Changed

- preferred examples and docs now use `createDerivedKeyCipher` with `kdf.input`.
- `derivePbkdf2` / `deriveEvpKdf` now use `input` instead of `passphrase`.
- `createPassphraseCipher(...)` remains compatible as a deprecated wrapper: it maps `passphrase` to `kdf.input` and delegates to `createDerivedKeyCipher(...)`.
- async KDF errors from the derived-key path now say `async derived-key cipher API`.
- RIPEMD160 is now implemented directly in `@jscrypto/classic/hashes`; removed the `@noble/hashes` dependency.

## v0.4.0 / 2026-07-15

### Changed

- changed classic hash components to use external hash implementations: `js-md5`, `js-sha1`, `js-sha256`, `js-sha3`, `js-sha512`, and `@noble/hashes` for RIPEMD-160.
- added `KECCAK512` as the accurate name for the CryptoJS-compatible SHA3 behavior, while keeping `SHA3` as a deprecated compatibility alias.
- kept `@jscrypto/classic` Node hash entry points externalized while preserving the self-contained browser hashes bundle.

## v0.3.1 / 2026-07-15

### Fixed

- fixed package versions for the `@jscrypto/core` and `@jscrypto/classic` npm release.
- fixed browser bundle banners to derive their version from each package's `package.json` during build.

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
