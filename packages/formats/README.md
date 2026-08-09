# @jscrypto/formats

Format components for `@jscrypto/core`.

```ts
import { createRegistry } from '@jscrypto/core';
import { opensslFormat } from '@jscrypto/formats/openssl';

const registry = createRegistry().use(opensslFormat);
```

Use `formatsPreset()` to register OpenSSL `Salted__` formatting.
