# @crypto/classic

Classic cipher, mode, padding, KDF, and format components for `@crypto`.

This package is the first compatibility preset for online-tools. It is CryptoJS-compatible where classic behavior depends on CryptoJS formats or KDFs.

## Install

```sh
npm install @crypto/core @crypto/classic
```

## Quick Start

```ts
import { registry } from '@crypto/classic';

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
import { registry } from '@crypto/classic';

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

## Components

- Ciphers: `aes`, `des`, `tripleDes`, `rc4`, `rc4Drop`.
- Modes: `cbc`, `cfb`, `ctr`, `ofb`, `ecb`.
- Paddings: `pkcs7`, `iso97971`, `ansiX923`, `iso10126`, `zeroPadding`, `noPadding`.
- KDFs: `pbkdf2`, `evpKdf`.
- Formats: `opensslFormat`.
- Preset: `classicPreset`.
- Registries: `registry`, `createClassicRegistry`.

## Custom Registry

```ts
import { createRegistry } from '@crypto/core';
import { aes, cbc, pkcs7 } from '@crypto/classic';

const registry = createRegistry()
  .use(aes)
  .use(cbc)
  .use(pkcs7);
```

## Browser Global

```html
<script src="node_modules/@crypto/classic/dist/crypto-classic.iife.min.js"></script>
<script>
  const cipher = cryptoClassic.registry.createCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    key,
    iv,
  });
</script>
```

AES-GCM is intentionally left out of this first release slice.
