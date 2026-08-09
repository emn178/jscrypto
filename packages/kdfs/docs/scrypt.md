# Scrypt

RFC 7914 scrypt key derivation component for `@jscrypto/core`.

Scrypt is intended for password-derived key material. It is memory-hard: raising
`N`, `r`, or `p` increases CPU and memory cost.

This module wraps `@noble/hashes/scrypt.js`.

## Usage

```ts
import { createRegistry } from '@jscrypto/core';
import { scryptPreset } from '@jscrypto/kdfs/scrypt';

const registry = createRegistry().use(scryptPreset);

const key = registry.derive({
  name: 'Scrypt',
  input: 'password',
  salt: new TextEncoder().encode('NaCl'),
  N: 1024,
  r: 8,
  p: 16,
  length: 64,
});
```

## Components

| Export | Registry name | Required params | Optional params |
| --- | --- | --- | --- |
| `scrypt` | `Scrypt` | `input`, `salt`, `N`, `r`, `p`, `length` | `maxmem` |

`N` must be a positive power of two. `input` and `salt` may be `Uint8Array` or
string values; strings are encoded as UTF-8.

## Direct Helper

```ts
import { deriveScrypt } from '@jscrypto/kdfs/scrypt';

const key = deriveScrypt({
  input: 'password',
  salt: 'salt',
  N: 16384,
  r: 8,
  p: 1,
  length: 32,
});
```

## Browser Files

| Export path | File |
| --- | --- |
| `@jscrypto/kdfs/scrypt/browser` | `dist/jscrypto-kdfs-scrypt.iife.min.js` |
| `@jscrypto/kdfs/scrypt/umd` | `dist/jscrypto-kdfs-scrypt.umd.min.js` |
