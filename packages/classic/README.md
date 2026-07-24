# @jscrypto/classic

Classic cipher, mode, padding, KDF, and format components for `@jscrypto`.

This package provides classic cipher, mode, padding, KDF, and format components. It is implemented without a runtime dependency on other crypto frameworks.

## Install

```sh
npm install @jscrypto/core @jscrypto/classic
```

## Quick Start

```ts
import { registry } from '@jscrypto/classic';

const cipher = registry.createCipher({
  cipher: 'AES',
  mode: 'CBC',
  padding: 'Pkcs7',
  key,
  iv,
});

const ciphertext = cipher.encrypt(plaintext);
const decrypted = cipher.decrypt(ciphertext);
```

## Derived-Key Encryption

```ts
import { registry } from '@jscrypto/classic';
import { classicHashesPreset } from '@jscrypto/classic/hashes';

registry.use(classicHashesPreset);

const cipher = registry.createDerivedKeyCipher({
  cipher: 'AES',
  mode: 'CBC',
  padding: 'Pkcs7',
  kdf: {
    name: 'EvpKDF',
    input: 'secret',
    iterations: 1,
    hash: 'MD5',
  },
  format: 'OpenSSL',
});

const encrypted = cipher.encrypt(plaintext);
const decrypted = cipher.decrypt(encrypted);
```

`createPassphraseCipher(...)` remains available as a deprecated compatibility alias.

## AES-GCM

GCM is an AEAD mode. It does not use padding, and encrypted output is `ciphertext || tag` by default. Decryption also supports detached tags by passing `tag`.

```ts
import { registry } from '@jscrypto/classic';

const cipher = registry.createCipher({
  cipher: 'AES',
  mode: 'GCM',
  key,
  iv: nonce,
  aad,
  tagLength: 16,
});

const sealed = cipher.encrypt(plaintext);
const decrypted = cipher.decrypt(sealed);
```

## Components

- Ciphers: `aes`, `des`, `tripleDes`, `rc4`, `rc4Drop`.
- Modes: `cbc`, `cfb`, `ctr`, `ofb`, `ecb`, `gcm`.
- Paddings: `pkcs7`, `iso97971`, `ansiX923`, `iso10126`, `zeroPadding`, `noPadding`.
- KDFs: `pbkdf2`, `evpKdf`.
- Formats: `opensslFormat`.
- Opt-in hashes: `@jscrypto/classic/hashes` with `classicHashesPreset`.
- Preset: `classicPreset` (does not register hashes).
- Registries: `registry`, `createClassicRegistry`.

## Hash Compatibility

`registry.use(classicHashesPreset)` registers MD5, SHA1, SHA224, SHA256, SHA384, SHA512, KECCAK512, deprecated SHA3, and RIPEMD160.

`SHA3` is kept as a deprecated legacy alias for Keccak-512. New code should use `KECCAK512`; a future NIST SHA3-512 component should use a distinct name.

## Custom Registry

```ts
import { createRegistry } from '@jscrypto/core';
import { aes, cbc, pkcs7 } from '@jscrypto/classic';

const registry = createRegistry()
  .use(aes)
  .use(cbc)
  .use(pkcs7);
```

## Browser Global

The classic browser bundle is not standalone; load `@jscrypto/core` before `@jscrypto/classic`.

```html
<script src="node_modules/@jscrypto/core/dist/jscrypto-core.iife.min.js"></script>
<script src="node_modules/@jscrypto/classic/dist/jscrypto-classic.iife.min.js"></script>
<script src="node_modules/@jscrypto/classic/dist/jscrypto-classic-hashes.iife.min.js"></script>
<script>
  jscryptoClassic.registry.use(jscryptoClassicHashes.classicHashesPreset);
  const cipher = jscryptoClassic.registry.createCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    key,
    iv,
  });
</script>
```
