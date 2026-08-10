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
import { gcmPreset } from '@jscrypto/modes/gcm';

const registry = createRegistry()
  .use(aesPreset)
  .use(gcmPreset);
const key = randomBytes(32);
const nonce = randomBytes(12);

const aead = registry.createAead({
  algorithm: 'AES-GCM',
  key,
});

const sealed = aead.seal(plaintext, { nonce, aad });
const opened = aead.open(sealed, { nonce, aad });

const sealer = aead.createSealer({ nonce, aad });
const first = sealer.process(plaintext.subarray(0, 32));
const last = sealer.finalize(plaintext.subarray(32));
```

`aesPreset` registers both the AES block cipher and the `AES-GCM` AEAD
component. AES-GCM composes the registered `AES` cipher with the registered
`GCM` mode at runtime, so standalone registries must also register `gcm` or
`gcmPreset` from `@jscrypto/modes`. `createAead` is preferred for new
authenticated-encryption code.

AEAD has no padding. `nonce` must be unique for a given key. `aad` is
authenticated but not encrypted. `seal()` appends the authentication tag;
`open()` also accepts a detached `tag`. AES-GCM sealers can emit ciphertext from
`process()` and append the tag from `finalize()`. Safe openers verify before
releasing plaintext, so `process()` returns empty chunks and `finalize()` returns
the plaintext after authentication succeeds.

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
