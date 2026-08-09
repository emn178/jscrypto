# AES

AES block cipher component for `@jscrypto/core`.

AES requires a mode for variable-length messages.

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

## Components

| Export | Registry name | Type | Block bytes | Key bytes |
| --- | --- | --- | --- | --- |
| `aes` | `AES` | Block cipher | 16 | 16, 24, 32 |

## Browser Files

| Export path | File |
| --- | --- |
| `@jscrypto/ciphers/aes/browser` | `dist/jscrypto-ciphers-aes.iife.min.js` |
| `@jscrypto/ciphers/aes/umd` | `dist/jscrypto-ciphers-aes.umd.min.js` |
