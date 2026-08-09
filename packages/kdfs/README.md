# @jscrypto/kdfs
[![NPM](https://img.shields.io/npm/v/@jscrypto/kdfs)](https://www.npmjs.com/package/@jscrypto/kdfs)
[![CDNJS](https://img.shields.io/jsdelivr/npm/hm/@jscrypto/kdfs)](https://www.jsdelivr.com/package/npm/@jscrypto/kdfs)

KDF components for `@jscrypto/core`.

## Demo
- [PBKDF2 Online](https://emn178.github.io/online-tools/kdf/pbkdf2/)
- [EvpKDF Online](https://emn178.github.io/online-tools/kdf/evpkdf/)
- [HKDF Online](https://emn178.github.io/online-tools/kdf/hkdf/)
- [Scrypt KDF Online](https://emn178.github.io/online-tools/kdf/scrypt/)
- [Argon2 KDF Online](https://emn178.github.io/online-tools/kdf/argon2/)

## Components

- [PBKDF2](./docs/pbkdf2.md)
- [EvpKDF](./docs/evpkdf.md)
- [HKDF](./docs/hkdf.md)
- [Scrypt](./docs/scrypt.md)
- [Argon2](./docs/argon2.md)

```ts
import { createRegistry } from '@jscrypto/core';
import { pbkdf2 } from '@jscrypto/kdfs/pbkdf2';

const registry = createRegistry().use(pbkdf2);
```

Each KDF group also exports a preset:

```ts
import { hkdfPreset } from '@jscrypto/kdfs/hkdf';
import { pbkdf2Preset } from '@jscrypto/kdfs/pbkdf2';

registry
  .use(pbkdf2Preset)
  .use(hkdfPreset);
```

Use `classicKdfsPreset()` to register the classic compatibility set: PBKDF2 and
EvpKDF.

Use `kdfsPreset()` to register the full KDF package set, including HKDF,
HKDF-Extract, HKDF-Expand, Scrypt, and Argon2.

## Browser

For browser apps, prefer `@jscrypto/suite/basic` plus independent KDF/hash bundles
instead of the full `@jscrypto/kdfs` bundle:

```html
<script src="jscrypto-core.iife.min.js"></script>
<script src="jscrypto-suite-basic.iife.min.js"></script>
<script src="jscrypto-hashes-sha256.iife.min.js"></script>
<script src="jscrypto-kdfs-hkdf.iife.min.js"></script>
<script>
  jscryptoSuiteBasic.registry
    .use(jscryptoHashesSha256.sha256Preset)
    .use(jscryptoKdfsHkdf.hkdfPreset);
</script>
```

The package still provides `@jscrypto/kdfs/browser` as a full convenience bundle,
but size-sensitive browser builds should load the specific subpath bundle they
need.
