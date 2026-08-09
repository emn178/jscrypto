# @jscrypto/core
[![NPM](https://img.shields.io/npm/v/@jscrypto/core)](https://www.npmjs.com/package/@jscrypto/core)
[![CDNJS](https://img.shields.io/jsdelivr/npm/hm/@jscrypto/core)](https://www.jsdelivr.com/package/npm/@jscrypto/core)

Core registry, component contracts, transform helpers, byte helpers, and shared errors for `@jscrypto` packages.

## Install

```sh
npm install @jscrypto/core
```

## Usage

`@jscrypto/core` provides the framework contracts and registry. It does not ship concrete ciphers or modes by itself. Install component packages for actual algorithms:

```sh
npm install @jscrypto/core @jscrypto/ciphers @jscrypto/modes @jscrypto/paddings
```

```ts
import { createRegistry, randomBytes } from '@jscrypto/core';
import { aes } from '@jscrypto/ciphers/aes';
import { cbc } from '@jscrypto/modes/cbc';
import { pkcs7 } from '@jscrypto/paddings/pkcs7';

const registry = createRegistry()
  .use(aes)
  .use(cbc)
  .use(pkcs7);

const key = randomBytes(32);
const iv = randomBytes(16);
const cipher = registry.createCipher({
  cipher: 'AES',
  mode: 'CBC',
  padding: 'Pkcs7',
  key,
});

const ciphertext = cipher.encrypt(plaintext, { iv });
```

Per-operation options are passed to facade methods rather than being fixed only at facade creation time. Core forwards mode-specific options without naming them; modes such as GCM may define options like `nonce`, `aad`, `tag`, or `tagLength`.

## What It Provides

- `createRegistry`: component registry with cipher facade and derived-key facade creation.
- `randomBytes(length)`: caller-owned random byte helper.
- Component contracts: cipher, mode, padding, KDF, format, and preset types.
- Transform contract: `process(input)` plus `finalize(input?)` for streaming.
- Byte helpers: `concatBytes`, `equalBytes`, `xorBytes`, and byte assertions.
- Block helpers: block-size, IV, and padding assertions.
- Errors: `CryptoError`, `DuplicateComponentError`, and `MissingComponentError`.

`@jscrypto/core` does not include concrete cryptographic algorithms. Use `@jscrypto/suite`, component packages, or custom components for actual ciphers, modes, paddings, KDFs, hashes, and formats.
