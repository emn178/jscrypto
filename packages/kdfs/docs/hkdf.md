# HKDF

RFC 5869 HKDF key derivation components for `@jscrypto/core`.

HKDF is not a password hashing function. Use PBKDF2, scrypt, Argon2id, or a
similar KDF for passwords. HKDF derives keys from existing high-entropy or
protocol-provided input keying material such as a shared secret, PSK, or master
secret.

This module does not include hash implementations. Register hashes through the
core registry, for example from `@jscrypto/hashes`.

The module exposes three RFC 5869 operation forms:

- `HKDF`: Extract + Expand.
- `HKDF-Extract`: IKM + salt -> PRK.
- `HKDF-Expand`: PRK + info -> OKM.

For Expand, `input` is a PRK, not raw IKM.

## Usage

```ts
import { createRegistry } from '@jscrypto/core';
import { hashesPreset } from '@jscrypto/hashes';
import { hkdfPreset } from '@jscrypto/kdfs/hkdf';

const registry = createRegistry()
  .use(hashesPreset)
  .use(hkdfPreset);

const okm = registry.derive({
  name: 'HKDF',
  input: sharedSecret,
  salt,
  info: new TextEncoder().encode('example:v1'),
  hash: 'SHA256',
  length: 32,
});
```

`hash` is required. `salt` is optional by RFC 5869, but recommended when
available. `info` should bind derived output to protocol or application context.

## Extract And Expand

```ts
const prk = registry.derive({
  name: 'HKDF-Extract',
  input: sharedSecret,
  salt,
  hash: 'SHA256',
});

const expanded = registry.derive({
  name: 'HKDF-Expand',
  input: prk,
  info: new TextEncoder().encode('example:v1'),
  hash: 'SHA256',
  length: 32,
});
```

## Components

| Export | Registry name | Required params | Optional/default params |
| --- | --- | --- | --- |
| `hkdf` | `HKDF` | `input`, `hash`, `length` | `salt`, `info` |
| `hkdfExtract` | `HKDF-Extract` | `input`, `hash` | `salt` |
| `hkdfExpand` | `HKDF-Expand` | `input`, `hash`, `length` | `info` |

## Direct Helpers

```ts
import { sha256 } from '@jscrypto/hashes/sha256';
import { deriveHkdf, expandHkdf, extractHkdf } from '@jscrypto/kdfs/hkdf';

const okm = deriveHkdf({
  input: sharedSecret,
  salt,
  info,
  hash: sha256,
  length: 32,
});
```

## Browser Files

| Export path | File |
| --- | --- |
| `@jscrypto/kdfs/hkdf/browser` | `dist/jscrypto-kdfs-hkdf.iife.min.js` |
| `@jscrypto/kdfs/hkdf/umd` | `dist/jscrypto-kdfs-hkdf.umd.min.js` |
