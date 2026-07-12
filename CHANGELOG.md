# Change Log

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
