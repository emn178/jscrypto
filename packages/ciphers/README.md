# @jscrypto/ciphers
[![NPM](https://img.shields.io/npm/v/@jscrypto/ciphers)](https://www.npmjs.com/package/@jscrypto/ciphers)
[![CDNJS](https://img.shields.io/jsdelivr/npm/hm/@jscrypto/ciphers)](https://www.jsdelivr.com/package/npm/@jscrypto/ciphers)

Cipher components for `@jscrypto/core`.

## Demo
[AES Encrypt Online](https://emn178.github.io/online-tools/aes/encrypt/)  
[AES Decrypt Online](https://emn178.github.io/online-tools/aes/decrypt/)  
[DES Encrypt Online](https://emn178.github.io/online-tools/des/encrypt/)  
[DES Decrypt Online](https://emn178.github.io/online-tools/des/decrypt/)  
[Triple DES Encrypt Online](https://emn178.github.io/online-tools/triple-des/encrypt/)  
[Triple DES Decrypt Online](https://emn178.github.io/online-tools/triple-des/decrypt/)  
[RC4 Encrypt Online](https://emn178.github.io/online-tools/rc4/encrypt/)  
[RC4 Decrypt Online](https://emn178.github.io/online-tools/rc4/decrypt/)  
[ChaCha20 Encrypt Online](https://emn178.github.io/online-tools/chacha20/encrypt/)  
[ChaCha20 Decrypt Online](https://emn178.github.io/online-tools/chacha20/decrypt/)  
[ChaCha20-Poly1305 Encrypt Online](https://emn178.github.io/online-tools/chacha20-poly1305/encrypt/)  
[ChaCha20-Poly1305 Decrypt Online](https://emn178.github.io/online-tools/chacha20-poly1305/decrypt/)
[Speck Encrypt Online](https://emn178.github.io/online-tools/speck/encrypt/)  
[Speck Decrypt Online](https://emn178.github.io/online-tools/speck/decrypt/)  

## Components

- [AES](./docs/aes.md)
- [DES](./docs/des.md)
- [Triple DES](./docs/triple-des.md)
- [RC4 and RC4Drop](./docs/rc4.md)
- [SPECK](./docs/speck.md)
- [ChaCha20 family](./docs/chacha20.md)

```ts
import { createRegistry } from '@jscrypto/core';
import { aes } from '@jscrypto/ciphers/aes';

const registry = createRegistry().use(aes);
```

Each cipher group also exports a preset:

```ts
import { chacha20Preset } from '@jscrypto/ciphers/chacha20';
import { speckPreset } from '@jscrypto/ciphers/speck';

registry
  .use(chacha20Preset)
  .use(speckPreset);
```

Use `classicCiphersPreset()` to register the classic compatibility set: AES, DES,
Triple DES, RC4, and RC4Drop.

Use `ciphersPreset()` to register the full cipher package set, including SPECK,
ChaCha20, XChaCha20, ChaCha20-Poly1305, and XChaCha20-Poly1305.

## Browser

For browser apps, prefer `@jscrypto/suite/basic` plus independent cipher bundles
instead of the full `@jscrypto/ciphers` bundle:

```html
<script src="jscrypto-core.iife.min.js"></script>
<script src="jscrypto-suite-basic.iife.min.js"></script>
<script src="jscrypto-ciphers-chacha20.iife.min.js"></script>
<script>
  jscryptoSuiteBasic.registry.use(jscryptoCiphersChacha20.chacha20Preset);
</script>
```

The package still provides `@jscrypto/ciphers/browser` as a full convenience
bundle, but feature pages and size-sensitive browser builds should load the
specific subpath bundle they need.
