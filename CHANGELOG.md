# Change Log

## v0.10.0 / 2026-08-09

### Added

- added Scrypt and Argon2 components to `@jscrypto/kdfs`.
- added `Pkcs5` as a PKCS#7-compatible padding alias.

### Removed

- removed the deprecated `@jscrypto/classic` compatibility aggregate. Use `@jscrypto/suite` or component packages instead.

## v0.9.1 / 2026-08-09

### Fixed

- classic build incorrectly included all ciphers.

## v0.9.0 / 2026-08-09

### Added

- added component packages: `@jscrypto/ciphers`, `@jscrypto/modes`, `@jscrypto/paddings`, `@jscrypto/kdfs`, `@jscrypto/formats`, and `@jscrypto/hashes`.
- added SPECK and ChaCha20 family components to `@jscrypto/ciphers`.
- added HKDF, HKDF-Extract, and HKDF-Expand components to `@jscrypto/kdfs`.
- added `@jscrypto/suite` as a convenience registry that registers the official component packages together.
- added `basicPreset` / `createBasicRegistry` and `allPreset` / `createAllRegistry` to `@jscrypto/suite`.
- added `@jscrypto/suite/basic` and `@jscrypto/suite/all` subpath exports plus matching browser bundles.
- added subpath exports such as `@jscrypto/ciphers/aes`, `@jscrypto/modes/cbc`, `@jscrypto/paddings/pkcs7`, and `@jscrypto/kdfs/pbkdf2`.
- added individual browser IIFE/UMD bundles for component subpaths such as `@jscrypto/ciphers/chacha20/browser`, `@jscrypto/ciphers/speck/browser`, and `@jscrypto/kdfs/hkdf/browser`.
- added per-component or per-family presets such as `aesPreset`, `speckPreset`, `chacha20Preset`, `pbkdf2Preset`, and `hkdfPreset`.
- added component documentation pages under `@jscrypto/ciphers/docs` and `@jscrypto/kdfs/docs`.

### Changed

- changed `@jscrypto/classic` into a compatibility aggregate that re-exports the new component packages.
- changed SPECK, ChaCha20, and HKDF from separate package repos into component subpaths of `@jscrypto/ciphers` and `@jscrypto/kdfs`.
- changed the default `@jscrypto/suite` singleton registry and `suitePreset` compatibility alias to use the basic preset.
- changed documentation to recommend `@jscrypto/suite` for a ready-to-use registry and component packages for focused imports.
- changed aggregate presets to compose smaller component presets.

## v0.8.0 / 2026-08-03

### Added

- added `mutableInput: true` as a transform creation hint so block modes can reuse caller-owned buffers when the selected mode can do so safely.
- added raw block cipher `encrypt(input, output)` and `decrypt(input, output)` methods for caller-owned output buffers.

### Changed

- changed classic AES, DES, and Triple DES internals to use the new raw block cipher buffer API.
- optimized the classic AES implementation with lookup tables for faster block encryption and decryption.
- changed ECB, CBC, CFB, CTR, OFB, and GCM modes to honor `mutableInput: true` where their transform logic can safely write into the input buffer.

### Removed

- removed the old single-argument block cipher `encryptBlock(block)` and `decryptBlock(block)` methods from the public component contract.
- removed deprecated compatibility APIs: `registry.createPassphraseCipher(...)`, `registerClassicHashes(registry)`, and the `SHA3` hash alias. Use `registry.createDerivedKeyCipher(...)`, `registry.use(classicHashesPreset)`, and `KECCAK512` instead.

## v0.7.0 / 2026-07-27

### Added

- added per-operation options for cipher facades, so IV, nonce, AAD, detached tag, and other mode-specific values can be passed to `encrypt`, `decrypt`, `createEncryptor`, and `createDecryptor`.
- added per-operation `salt` support for derived-key cipher facades.
- added public `randomBytes(length)` to `@jscrypto/core`.
- added `ModeComponent.getIvSize(...)` so modes define derived-key IV material length.

### Changed

- changed README examples to prefer reusable cipher facades with operation-specific IV/nonce/salt options.
- changed `createDerivedKeyCipher(...)` to derive IV material according to the selected mode instead of a public `ivSize` option.
- changed `createDerivedKeyCipher(...)` so OpenSSL format serializes/parses salt but does not generate salt in the new derived-key API.
- kept salt validation inside individual KDF implementations instead of exposing KDF salt policy in core component metadata.
- removed unused `ModeComponent` metadata fields `requiredBlockSize` and `aead`.

### Fixed

- prevented operation options from overriding reserved facade creation keys such as `cipher`, `mode`, `padding`, `key`, `kdf`, and `format`.
- made `randomBytes(length)` fill large buffers in Web Crypto-compatible chunks.

## v0.6.0 / 2026-07-24

### Changed

- changed the `@jscrypto/classic` browser IIFE/UMD bundles to depend on the `@jscrypto/core` browser global instead of bundling core internally.
- added `classicHashesPreset` as the preferred opt-in hash registration API; `registerClassicHashes(registry)` remains as a deprecated compatibility helper.
- changed CI to build npm package tarballs once on Node 24 and run runtime tests against those packaged outputs across supported Node versions.

## v0.5.1 / 2026-07-22

### Changed

- changed KDF components and `registry.derive(...)` to be synchronous-only and return `Uint8Array`.
- added runtime validation that custom KDF components return `Uint8Array`.

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
