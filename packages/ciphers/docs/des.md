# DES

DES block cipher component for compatibility with legacy data.

DES uses an 8-byte key and an 8-byte block size. It is not recommended for new
cryptographic designs.

## Usage

```ts
import { createRegistry } from '@jscrypto/core';
import { desPreset } from '@jscrypto/ciphers/des';

const registry = createRegistry().use(desPreset);
```

## Components

| Export | Registry name | Type | Block bytes | Key bytes |
| --- | --- | --- | --- | --- |
| `des` | `DES` | Block cipher | 8 | 8 |

## Browser Files

| Export path | File |
| --- | --- |
| `@jscrypto/ciphers/des/browser` | `dist/jscrypto-ciphers-des.iife.min.js` |
| `@jscrypto/ciphers/des/umd` | `dist/jscrypto-ciphers-des.umd.min.js` |
