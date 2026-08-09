# EvpKDF

OpenSSL-compatible EVP key derivation component for `@jscrypto/core`.

EvpKDF is kept for compatibility with OpenSSL-style passphrase encryption and
legacy data. For new password-based designs, prefer a modern
password KDF such as PBKDF2 with a high iteration count, scrypt, or Argon2id.

When used through the component API, the default hash is `MD5` for compatibility.

## Usage

```ts
import { createRegistry } from '@jscrypto/core';
import { hashesPreset } from '@jscrypto/hashes';
import { evpKdfPreset } from '@jscrypto/kdfs/evpkdf';

const registry = createRegistry()
  .use(hashesPreset)
  .use(evpKdfPreset);

const key = registry.derive({
  name: 'EvpKDF',
  input: 'secret',
  salt,
  iterations: 1,
  hash: 'MD5',
  length: 48,
});
```

## Components

| Export | Registry name | Required params | Optional/default params |
| --- | --- | --- | --- |
| `evpKdf` | `EvpKDF` | `input`, `salt`, `length` | `iterations`, default `1`; `hash`, default `MD5` |

`deriveEvpKdf` is also exported as a direct helper. It requires a concrete
`HashComponent` instead of a hash name.

## Browser Files

| Export path | File |
| --- | --- |
| `@jscrypto/kdfs/evpkdf/browser` | `dist/jscrypto-kdfs-evpkdf.iife.min.js` |
| `@jscrypto/kdfs/evpkdf/umd` | `dist/jscrypto-kdfs-evpkdf.umd.min.js` |
