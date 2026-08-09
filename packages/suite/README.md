# @jscrypto/suite
[![NPM](https://img.shields.io/npm/v/@jscrypto/suite)](https://www.npmjs.com/package/@jscrypto/suite)
[![CDNJS](https://img.shields.io/jsdelivr/npm/hm/@jscrypto/suite)](https://www.jsdelivr.com/package/npm/@jscrypto/suite)

Convenience registries for official `@jscrypto` component packages.

The default `registry` uses `basicPreset`, which contains AES, common modes,
Pkcs7/NoPadding, PBKDF2, HKDF, OpenSSL format support, and bundled hash adapters.
Use `allPreset` when compatibility algorithms such as DES, Triple DES, RC4,
SPECK, ChaCha20, EvpKDF, and all classic paddings should be registered too.

```ts
import { registry } from '@jscrypto/suite';

const cipher = registry.createCipher({
  cipher: 'AES',
  mode: 'CBC',
  padding: 'Pkcs7',
  key,
});
```

```ts
import { createAllRegistry } from '@jscrypto/suite/all';

const registry = createAllRegistry();
```

`suitePreset` is an alias of `basicPreset` for compatibility with the initial
suite API.
