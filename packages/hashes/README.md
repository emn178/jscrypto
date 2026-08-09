# @jscrypto/hashes
[![NPM](https://img.shields.io/npm/v/@jscrypto/hashes)](https://www.npmjs.com/package/@jscrypto/hashes)
[![CDNJS](https://img.shields.io/jsdelivr/npm/hm/@jscrypto/hashes)](https://www.jsdelivr.com/package/npm/@jscrypto/hashes)

Hash components for `@jscrypto/core` KDFs.

```ts
import { createRegistry } from '@jscrypto/core';
import { hashesPreset } from '@jscrypto/hashes';

const registry = createRegistry().use(hashesPreset);
```

The preset registers MD5, SHA1, SHA224, SHA256, SHA384, SHA512, KECCAK512, and RIPEMD160.
