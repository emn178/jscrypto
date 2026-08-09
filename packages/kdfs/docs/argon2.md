# Argon2

Argon2 key derivation component for `@jscrypto/core`.

Argon2 is intended for password-derived key material. This component supports
Argon2id, Argon2i, and Argon2d through the `mode` option. Argon2id is the
default and is generally the preferred variant for password hashing and key
derivation.

This module wraps `@noble/hashes/argon2.js`.

## Usage

```ts
import { createRegistry } from '@jscrypto/core';
import { argon2Preset } from '@jscrypto/kdfs/argon2';

const registry = createRegistry().use(argon2Preset);

const key = registry.derive({
  name: 'Argon2',
  input: 'password',
  salt: new TextEncoder().encode('somesalt'),
  mode: 'id',
  t: 2,
  m: 19456,
  p: 1,
  length: 32,
});
```

## Components

| Export | Registry name | Required params | Optional/default params |
| --- | --- | --- | --- |
| `argon2` | `Argon2` | `input`, `salt`, `t`, `m`, `p`, `length` | `mode: 'id'`, `maxmem` |

`mode` may be `'id'`, `'i'`, or `'d'`. `input` and `salt` may be `Uint8Array`
or string values; strings are encoded as UTF-8.

## Direct Helper

```ts
import { deriveArgon2 } from '@jscrypto/kdfs/argon2';

const key = deriveArgon2({
  input: 'password',
  salt: 'somesalt',
  mode: 'id',
  t: 2,
  m: 19456,
  p: 1,
  length: 32,
});
```

## Browser Files

| Export path | File |
| --- | --- |
| `@jscrypto/kdfs/argon2/browser` | `dist/jscrypto-kdfs-argon2.iife.min.js` |
| `@jscrypto/kdfs/argon2/umd` | `dist/jscrypto-kdfs-argon2.umd.min.js` |
