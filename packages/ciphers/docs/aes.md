# AES

AES block cipher and AES-GCM AEAD components for `@jscrypto/core`.

AES block cipher requires a mode for variable-length messages. Prefer the
`AES-GCM` AEAD component for authenticated encryption.

## Usage

```ts
import { createRegistry } from '@jscrypto/core';
import { aesPreset } from '@jscrypto/ciphers/aes';
import { cbc } from '@jscrypto/modes/cbc';
import { pkcs7 } from '@jscrypto/paddings/pkcs7';

const registry = createRegistry()
  .use(aesPreset)
  .use(cbc)
  .use(pkcs7);
```

Authenticated encryption with AES-GCM:

```ts
import { createRegistry, randomBytes } from '@jscrypto/core';
import { aesPreset } from '@jscrypto/ciphers/aes';

const registry = createRegistry().use(aesPreset);
const key = randomBytes(32);
const nonce = randomBytes(12);

const aead = registry.createAead({
  algorithm: 'AES-GCM',
  key,
});

const sealed = aead.seal(plaintext, { nonce, aad });
const opened = aead.open(sealed, { nonce, aad });
```

`aesPreset` registers both the AES block cipher and the `AES-GCM` AEAD
component. Compatibility `createCipher({ cipher: 'AES', mode: 'GCM' })` remains
available when the GCM mode from `@jscrypto/modes` is also registered, but
`createAead` is preferred for new code.

AEAD has no padding. `nonce` must be unique for a given key. `aad` is
authenticated but not encrypted. `seal()` appends the authentication tag;
`open()` also accepts a detached `tag`.

## Components

| Export | Registry name | Type | Block bytes | Key bytes |
| --- | --- | --- | --- | --- |
| `aes` | `AES` | Block cipher | 16 | 16, 24, 32 |
| `aesGcm` | `AES-GCM` | AEAD | — | 16, 24, 32 |

`AES-GCM` recommends a 12-byte nonce and supports tag lengths 4–16 bytes.

## Browser Files

| Export path | File |
| --- | --- |
| `@jscrypto/ciphers/aes/browser` | `dist/jscrypto-ciphers-aes.iife.min.js` |
| `@jscrypto/ciphers/aes/umd` | `dist/jscrypto-ciphers-aes.umd.min.js` |
