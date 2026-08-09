# @jscrypto/formats
[![NPM](https://img.shields.io/npm/v/@jscrypto/formats)](https://www.npmjs.com/package/@jscrypto/formats)
[![CDNJS](https://img.shields.io/jsdelivr/npm/hm/@jscrypto/formats)](https://www.jsdelivr.com/package/npm/@jscrypto/formats)

Format components for `@jscrypto/core`.

```ts
import { createRegistry } from '@jscrypto/core';
import { opensslFormat } from '@jscrypto/formats/openssl';

const registry = createRegistry().use(opensslFormat);
```

Use `formatsPreset()` to register OpenSSL `Salted__` formatting.
