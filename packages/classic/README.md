# @jscrypto/classic
[![NPM](https://img.shields.io/npm/v/@jscrypto/classic)](https://www.npmjs.com/package/@jscrypto/classic)
[![CDNJS](https://img.shields.io/jsdelivr/npm/hm/@jscrypto/classic)](https://www.jsdelivr.com/package/npm/@jscrypto/classic)

Classic cipher, mode, padding, KDF, and format components for `@jscrypto`.

This package provides classic cipher, mode, padding, KDF, and format components for `@jscrypto`.

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

For performance-sensitive paths, `mutableInput: true` lets modes reuse caller-owned input buffers when safe. Treat input passed with this option as consumed.

```ts
const ciphertext = cipher.encrypt(mutablePlaintext, { iv, mutableInput: true });
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
  // CBC derives a 16-byte IV from AES's block size.
  format: 'OpenSSL',
});

const encrypted = cipher.encrypt(plaintext, { salt });
const decrypted = cipher.decrypt(encrypted);
```

The explicit example above derives an AES-128 key. When `keySize` is omitted, AES defaults to a 32-byte key. CBC derives a 16-byte IV from AES's block size:

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
  // CBC derived IV: 16 bytes
  format: 'OpenSSL',
});
```

OpenSSL format stores the salt in the `Salted__` envelope, so decrypt normally reads it from the ciphertext.

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

const sealed = cipher.encrypt(plaintext, { nonce, aad });
const decrypted = cipher.decrypt(sealed, { nonce, aad });

// The default appended tag length is 16 bytes. If you choose a different
// appended tag length, pass the same value during decrypt.
const shortTagSealed = cipher.encrypt(plaintext, { nonce, aad, tagLength: 12 });
const shortTagDecrypted = cipher.decrypt(shortTagSealed, { nonce, aad, tagLength: 12 });
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

`registry.use(classicHashesPreset)` registers MD5, SHA1, SHA224, SHA256, SHA384, SHA512, KECCAK512, and RIPEMD160.

`KECCAK512` is Keccak-512. NIST SHA3-512 is not included yet and should use a distinct name if added later.

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
