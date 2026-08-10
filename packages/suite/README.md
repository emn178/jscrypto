# @jscrypto/suite
[![NPM](https://img.shields.io/npm/v/@jscrypto/suite)](https://www.npmjs.com/package/@jscrypto/suite)
[![CDNJS](https://img.shields.io/jsdelivr/npm/hm/@jscrypto/suite)](https://www.jsdelivr.com/package/npm/@jscrypto/suite)

Convenience registries for official `@jscrypto` component packages.

The default `registry` uses `basicPreset`, the recommended starting point for
new applications. It contains:

- AES and AES-GCM AEAD
- CBC, CFB, CTR, OFB, ECB, and compatibility GCM
- Pkcs7, Pkcs5, and NoPadding
- PBKDF2 and HKDF
- OpenSSL `Salted__` format support
- bundled hash adapters

Use `allPreset` or `@jscrypto/suite/all` when compatibility algorithms should
also be registered:

- DES, Triple DES, RC4, RC4Drop
- SPECK
- ChaCha20, XChaCha20, ChaCha20-Poly1305, XChaCha20-Poly1305
- EvpKDF, Scrypt, and Argon2
- all padding components

```ts
import { registry } from '@jscrypto/suite';

const cipher = registry.createCipher({
  cipher: 'AES',
  mode: 'CBC',
  padding: 'Pkcs7',
  key,
});
```

Authenticated encryption:

```ts
const aead = registry.createAead({
  algorithm: 'AES-GCM',
  key,
});

const sealed = aead.seal(plaintext, { nonce, aad });
```
```ts
import { createAllRegistry } from '@jscrypto/suite/all';

const registry = createAllRegistry();
```

`suitePreset` is an alias of `basicPreset` for compatibility with the initial
suite API.
