# @jscrypto/modes
[![NPM](https://img.shields.io/npm/v/@jscrypto/modes)](https://www.npmjs.com/package/@jscrypto/modes)
[![CDNJS](https://img.shields.io/jsdelivr/npm/hm/@jscrypto/modes)](https://www.jsdelivr.com/package/npm/@jscrypto/modes)

Mode components for `@jscrypto/core` block ciphers.

```ts
import { createRegistry } from '@jscrypto/core';
import { cbc } from '@jscrypto/modes/cbc';

const registry = createRegistry().use(cbc);
```

Use `modesPreset()` to register CBC, CFB, CTR, ECB, GCM, and OFB together.
