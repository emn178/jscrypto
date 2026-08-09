# @jscrypto/modes

Mode components for `@jscrypto/core` block ciphers.

```ts
import { createRegistry } from '@jscrypto/core';
import { cbc } from '@jscrypto/modes/cbc';

const registry = createRegistry().use(cbc);
```

Use `modesPreset()` to register CBC, CFB, CTR, ECB, GCM, and OFB together.
