# @jscrypto/classic

Classic cipher, mode, padding, KDF, and format components for `@jscrypto`.

This package provides classic cipher, mode, padding, KDF, and format components. It is implemented without a runtime dependency on other crypto frameworks.

## Install

```sh
npm install @jscrypto/core @jscrypto/classic
```

## Quick Start

```ts
import { randomBytes } from '@jscrypto/core';
import { registry } from '@jscrypto/classic';

const key = randomBytes(32);
const iv = randomBytes(16);
const cipher = registry.createCipher({
  cipher: 'AES',
  mode: 'CBC',
  padding: 'Pkcs7',
  key,
});

const ciphertext = cipher.encrypt(plaintext, { iv });
const decrypted = cipher.decrypt(ciphertext, { iv });
```

## Derived-Key Encryption

```ts
import { randomBytes } from '@jscrypto/core';
import { registry } from '@jscrypto/classic';
import { classicHashesPreset } from '@jscrypto/classic/hashes';

registry.use(classicHashesPreset);

const salt = randomBytes(8);
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
  keySize: 16,
  ivSize: 16,
  format: 'OpenSSL',
});

const encrypted = cipher.encrypt(plaintext, { salt });
const decrypted = cipher.decrypt(encrypted);
```

The explicit example above derives an AES-128 key. When `keySize` and `ivSize` are omitted, AES defaults to a 32-byte key and a 16-byte IV:

```ts
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
  // keySize: 32
  // ivSize: 16
  format: 'OpenSSL',
});
```

OpenSSL format stores the salt in the `Salted__` envelope, so decrypt normally reads it from the ciphertext. `createPassphraseCipher(...)` remains available as a deprecated compatibility alias that preserves passphrase/OpenSSL convenience behavior.

## AES-GCM

GCM is an AEAD mode. It does not use padding, and encrypted output is `ciphertext || tag` by default. Decryption also supports detached tags by passing `tag`.

```ts
import { randomBytes } from '@jscrypto/core';
import { registry } from '@jscrypto/classic';

const key = randomBytes(32);
const nonce = randomBytes(12);
const aad = new TextEncoder().encode('metadata');
const cipher = registry.createCipher({
  cipher: 'AES',
  mode: 'GCM',
  key,
});

const sealed = cipher.encrypt(plaintext, { nonce, aad, tagLength: 16 });
const decrypted = cipher.decrypt(sealed, { nonce, aad });
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
<script>
  const key = jscryptoCore.randomBytes(32);
  const iv = jscryptoCore.randomBytes(16);
  const cipher = jscryptoClassic.registry.createCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    key,
  });
  const ciphertext = cipher.encrypt(plaintext, { iv });
</script>
```

Load `jscrypto-classic-hashes.iife.min.js` only when browser code uses KDFs that resolve classic hash components.
