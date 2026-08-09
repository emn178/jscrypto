# Triple DES

Triple DES block cipher component for compatibility with legacy data.

Triple DES accepts 16-byte two-key and 24-byte three-key keys. It uses an 8-byte
block size and is not recommended for new cryptographic designs.

## Usage

```ts
import { createRegistry } from '@jscrypto/core';
import { tripleDesPreset } from '@jscrypto/ciphers/triple-des';

const registry = createRegistry().use(tripleDesPreset);
```

## Components

| Export | Registry name | Type | Block bytes | Key bytes |
| --- | --- | --- | --- | --- |
| `tripleDes` | `TripleDES` | Block cipher | 8 | 16, 24 |

## Browser Files

| Export path | File |
| --- | --- |
| `@jscrypto/ciphers/triple-des/browser` | `dist/jscrypto-ciphers-triple-des.iife.min.js` |
| `@jscrypto/ciphers/triple-des/umd` | `dist/jscrypto-ciphers-triple-des.umd.min.js` |
