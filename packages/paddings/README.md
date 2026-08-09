# @jscrypto/paddings

Padding components for `@jscrypto/core` block cipher modes.

```ts
import { createRegistry } from '@jscrypto/core';
import { pkcs7 } from '@jscrypto/paddings/pkcs7';

const registry = createRegistry().use(pkcs7);
```

Use `paddingsPreset()` to register the classic padding set together.
