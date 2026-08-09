# PBKDF2

PBKDF2 key derivation component for `@jscrypto/core`.

PBKDF2 requires `input`, `salt`, `iterations`, `length`, and a registered hash.
When used through the component API, the default hash is `SHA256`.

## Usage

```ts
import { createRegistry } from '@jscrypto/core';
import { hashesPreset } from '@jscrypto/hashes';
import { pbkdf2Preset } from '@jscrypto/kdfs/pbkdf2';

const registry = createRegistry()
  .use(hashesPreset)
  .use(pbkdf2Preset);

const key = registry.derive({
  name: 'PBKDF2',
  input: 'secret',
  salt,
  iterations: 100000,
  hash: 'SHA256',
  length: 32,
});
```

## Components

| Export | Registry name | Required params | Optional/default params |
| --- | --- | --- | --- |
| `pbkdf2` | `PBKDF2` | `input`, `salt`, `iterations`, `length` | `hash`, default `SHA256` |

`derivePbkdf2` is also exported as a direct helper. It requires a concrete
`HashComponent` instead of a hash name.

## Browser Files

| Export path | File |
| --- | --- |
| `@jscrypto/kdfs/pbkdf2/browser` | `dist/jscrypto-kdfs-pbkdf2.iife.min.js` |
| `@jscrypto/kdfs/pbkdf2/umd` | `dist/jscrypto-kdfs-pbkdf2.umd.min.js` |
