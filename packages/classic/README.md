# @jscrypto/classic

Classic cipher, mode, padding, KDF, and format components for `@jscrypto`.

This package is the first compatibility preset for online-tools. It is CryptoJS-compatible where classic behavior depends on CryptoJS formats or KDFs.

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

## Passphrase Encryption

```ts
import { registry } from '@jscrypto/classic';

const cipher = registry.createPassphraseCipher({
  cipher: 'AES',
  mode: 'CBC',
  padding: 'Pkcs7',
  passphrase: 'secret',
  kdf: {
    name: 'EvpKDF',
    iterations: 1,
    hash: 'MD5',
  },
  format: 'OpenSSL',
});

const encrypted = cipher.encrypt(plaintext);
const decrypted = cipher.decrypt(encrypted);
```

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
- Preset: `classicPreset`.
- Registries: `registry`, `createClassicRegistry`.

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

```html
<script src="node_modules/@jscrypto/classic/dist/jscrypto-classic.iife.min.js"></script>
<script>
  const cipher = jscryptoClassic.registry.createCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    key,
    iv,
  });
</script>
```
