# AES

AES block cipher plus AES-GCM and AES-CCM AEAD components for `@jscrypto/core`.

AES block cipher requires a mode for variable-length messages. Prefer the
`AES-GCM` or `AES-CCM` AEAD components for authenticated encryption.

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

Authenticated encryption with AES-CCM:

```ts
import { createRegistry, randomBytes } from '@jscrypto/core';
import { aesPreset } from '@jscrypto/ciphers/aes';

const registry = createRegistry().use(aesPreset);
const key = randomBytes(32);
const nonce = randomBytes(12);

const aead = registry.createAead({
  algorithm: 'AES-CCM',
  key,
});

const sealed = aead.seal(plaintext, {
  nonce,
  aad,
  tagLength: 8,
});
const opened = aead.open(sealed, {
  nonce,
  aad,
  tagLength: 8,
});
```

`aesPreset` registers the AES block cipher plus the `AES-GCM` and `AES-CCM`
AEAD components. AES-GCM composes the registered `AES` cipher with the
registered `GCM` mode at runtime, so standalone registries must also register
`gcm` or `gcmPreset` from `@jscrypto/modes`. AES-CCM only needs the registered
`AES` block cipher from the same preset. `createAead` is preferred for new
authenticated-encryption code. Do not use `createCipher({ mode: 'CCM' })`;
AES-CCM is AEAD-only.

AEAD has no padding. `nonce` must be unique for a given key. `aad` is
authenticated but not encrypted. `seal()` appends the authentication tag;
`open()` also accepts a detached `tag`.

AES-GCM sealers can emit ciphertext from `process()` and append the tag from
`finalize()`. AES-CCM buffers until `finalize()` because the plaintext length
is part of the first authentication block. Safe openers verify before releasing
plaintext.

AES-CCM nonce length must be 7..13 bytes. Nonce length controls the maximum
plaintext size (`L = 15 - nonce.length`). For example, a 13-byte nonce allows
at most 65535 plaintext bytes, while a 12-byte nonce allows at most 16777215
bytes. Tag length defaults to 16 and must be one of 4, 6, 8, 10, 12, 14, or 16
bytes.

## Components

| Export | Registry name | Type | Block bytes | Key bytes |
| --- | --- | --- | --- | --- |
| `aes` | `AES` | Block cipher | 16 | 16, 24, 32 |
| `aesGcm` | `AES-GCM` | AEAD | — | 16, 24, 32 |
| `aesCcm` | `AES-CCM` | AEAD | — | 16, 24, 32 |

`AES-GCM` recommends a 12-byte nonce and supports tag lengths 4–16 bytes.
`AES-CCM` recommends a 12-byte nonce, accepts nonce lengths 7–13 bytes, and
supports even tag lengths 4–16 bytes.

## Browser Files

| Export path | File |
| --- | --- |
| `@jscrypto/ciphers/aes/browser` | `dist/jscrypto-ciphers-aes.iife.min.js` |
| `@jscrypto/ciphers/aes/umd` | `dist/jscrypto-ciphers-aes.umd.min.js` |
