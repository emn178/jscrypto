# @jscrypto/core

Core registry, component contracts, transform helpers, byte helpers, and shared errors for `@jscrypto` packages.

## Install

```sh
npm install @jscrypto/core
```

## Usage

```ts
import { createRegistry } from '@jscrypto/core';
import { aes, cbc, pkcs7 } from '@jscrypto/classic';

const registry = createRegistry()
  .use(aes)
  .use(cbc)
  .use(pkcs7);

const cipher = registry.createCipher({
  cipher: 'AES',
  mode: 'CBC',
  padding: 'Pkcs7',
  key,
  iv,
});

const ciphertext = cipher.encrypt(plaintext);
```

## What It Provides

- `createRegistry`: component registry with cipher facade and passphrase facade creation.
- Component contracts: cipher, mode, padding, KDF, format, and preset types.
- Transform contract: `process(input)` plus `finalize(input?)` for streaming.
- Byte helpers: `concatBytes`, `equalBytes`, `xorBytes`, and byte assertions.
- Block helpers: block-size, IV, and padding assertions.
- Errors: `CryptoError`, `DuplicateComponentError`, and `MissingComponentError`.

`@jscrypto/core` does not include concrete cryptographic algorithms. Use `@jscrypto/classic` or custom components for actual ciphers, modes, paddings, KDFs, and formats.
