# @jscrypto/paddings
[![NPM](https://img.shields.io/npm/v/@jscrypto/paddings)](https://www.npmjs.com/package/@jscrypto/paddings)
[![CDNJS](https://img.shields.io/jsdelivr/npm/hm/@jscrypto/paddings)](https://www.jsdelivr.com/package/npm/@jscrypto/paddings)

Padding components for `@jscrypto/core` block cipher modes.

Available components:

- `pkcs7` / `Pkcs7`
- `pkcs5` / `Pkcs5`, a compatibility alias that uses PKCS#7 padding semantics
- `ansiX923` / `AnsiX923`
- `iso10126` / `Iso10126`
- `iso97971` / `Iso97971`
- `zeroPadding` / `ZeroPadding`
- `noPadding` / `NoPadding`

```ts
import { createRegistry } from '@jscrypto/core';
import { pkcs7 } from '@jscrypto/paddings/pkcs7';

const registry = createRegistry().use(pkcs7);
```

Use `paddingsPreset()` to register the classic padding set together.
