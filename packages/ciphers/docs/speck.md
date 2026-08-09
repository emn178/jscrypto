# SPECK

SPECK block cipher components for `@jscrypto/core`.

This module adapts `js-speck` and registers each SPECK variant as a fixed-size
block cipher component. SPECK is a niche, legacy, lightweight block cipher
family. Do not treat it as a default recommendation for new encryption designs.

Raw SPECK has no mode, padding, IV, KDF, salt, or authentication by itself.
Compose modes and paddings from `@jscrypto/modes` and `@jscrypto/paddings` when
a protocol specifically requires them. Modes can be composed only when their
structural requirements are met; for example, GCM requires a 128-bit block cipher,
so only SPECK128 variants are structurally compatible.

## Usage

```ts
import { createRegistry } from '@jscrypto/core';
import { cbc } from '@jscrypto/modes/cbc';
import { pkcs7 } from '@jscrypto/paddings/pkcs7';
import { speckPreset } from '@jscrypto/ciphers/speck';

const registry = createRegistry()
  .use(speckPreset)
  .use(cbc)
  .use(pkcs7);

const cipher = registry.createCipher({
  cipher: 'SPECK64/128',
  mode: 'CBC',
  padding: 'Pkcs7',
  key,
  iv,
});
```

## Direct Helper

```ts
import { createSpeckCipher } from '@jscrypto/ciphers/speck';

const cipher = createSpeckCipher('64-128', key);
const output = new Uint8Array(plaintextBlock.length);
cipher.encrypt(plaintextBlock, output);
```

There is no default variant. Always pass an explicit variant such as `64-128`.

## Components

| Export | Registry name | Block bytes | Key bytes |
| --- | --- | --- | --- |
| `speck32_64` | `SPECK32/64` | 4 | 8 |
| `speck48_72` | `SPECK48/72` | 6 | 9 |
| `speck48_96` | `SPECK48/96` | 6 | 12 |
| `speck64_96` | `SPECK64/96` | 8 | 12 |
| `speck64_128` | `SPECK64/128` | 8 | 16 |
| `speck96_96` | `SPECK96/96` | 12 | 12 |
| `speck96_144` | `SPECK96/144` | 12 | 18 |
| `speck128_128` | `SPECK128/128` | 16 | 16 |
| `speck128_192` | `SPECK128/192` | 16 | 24 |
| `speck128_256` | `SPECK128/256` | 16 | 32 |

Key length alone is not enough to choose a variant. For example, 12-byte keys are
shared by SPECK48/96, SPECK64/96, and SPECK96/96.

## Browser Files

| Export path | File |
| --- | --- |
| `@jscrypto/ciphers/speck/browser` | `dist/jscrypto-ciphers-speck.iife.min.js` |
| `@jscrypto/ciphers/speck/umd` | `dist/jscrypto-ciphers-speck.umd.min.js` |
