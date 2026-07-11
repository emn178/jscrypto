# @crypto

Composable cryptography components for JavaScript and TypeScript.

`@crypto` is a small Uint8Array-first framework for wiring ciphers, modes, paddings, KDFs, formats, and presets through one registry. The first release focuses on the classic CryptoJS-compatible features currently needed by online-tools.

This project is not affiliated with Node.js `crypto`, the Web Crypto API, or npm.

## Packages

- `@crypto/core`: registry, component contracts, transform helpers, byte helpers, and shared errors.
- `@crypto/classic`: AES, DES, Triple DES, RC4, RC4Drop, CBC, CFB, CTR, OFB, ECB, classic paddings, PBKDF2, EvpKDF, and OpenSSL `Salted__` formatting.

The public package count is intentionally small. `@crypto/classic` still keeps internal modules split by cipher, mode, padding, KDF, format, adapter, and preset so those boundaries stay testable and can be split later if the need becomes real.

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

`createCipher` returns a reusable facade. Each `encrypt` or `decrypt` call creates a fresh transform internally, so the facade can be reused safely for multiple one-shot calls.

## Streaming

```ts
import { concatBytes } from '@crypto/core';
import { registry } from '@crypto/classic';

const cipher = registry.createCipher({
  cipher: 'AES',
  mode: 'CBC',
  padding: 'Pkcs7',
  key,
  iv,
});

const encryptor = cipher.createEncryptor();
const ciphertext = concatBytes(
  encryptor.process(chunk1),
  encryptor.process(chunk2),
  encryptor.finalize(),
);

const decryptor = cipher.createDecryptor();
const plaintext = concatBytes(
  decryptor.process(ciphertext.subarray(0, 7)),
  decryptor.process(ciphertext.subarray(7)),
  decryptor.finalize(),
);
```

## Passphrases

Passphrase ciphers derive key and IV through a KDF, then optionally wrap salt and ciphertext through a format component.

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

The passphrase API also supports streaming:

```ts
import { concatBytes } from '@crypto/core';

const encryptor = cipher.createEncryptor();
const encrypted = concatBytes(
  encryptor.process(chunk1),
  encryptor.process(chunk2),
  encryptor.finalize(),
);
```

## Stream Ciphers

Stream ciphers do not use mode, padding, or IV.

```ts
import { registry } from '@crypto/classic';

const cipher = registry.createCipher({
  cipher: 'RC4Drop',
  key,
  drop: 256,
});

const ciphertext = cipher.encrypt(plaintext);
```

## Custom Registry

The classic package exports a singleton `registry` for normal use and a factory when isolation is useful.

```ts
import { createRegistry } from '@crypto/core';
import { aes, cbc, pkcs7 } from '@crypto/classic';

const registry = createRegistry()
  .use(aes)
  .use(cbc)
  .use(pkcs7);
```

## Browser Builds

Both packages ship ESM, CommonJS, IIFE, and UMD outputs.

```ts
import { createRegistry } from '@crypto/core';
import { registry } from '@crypto/classic';
```

```html
<script src="node_modules/@crypto/core/dist/crypto-core.iife.min.js"></script>
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

## Supported Classic Components

- Ciphers: AES, DES, Triple DES, RC4, RC4Drop.
- Modes: CBC, CFB, CTR, OFB, ECB.
- Paddings: Pkcs7, Iso97971, AnsiX923, Iso10126, ZeroPadding, NoPadding.
- KDFs: PBKDF2, EvpKDF.
- Formats: OpenSSL `Salted__`.

AES-GCM is planned but not part of this first classic slice.

## Development

```sh
npm install
npm run build
npm test
npm run coverage
```

`npm run build` creates ESM, CommonJS, IIFE, and UMD bundles for each published package. `npm run coverage` writes text output and an HTML report under `coverage/`.

## Security

This first release focuses on classic online-tools compatibility. Prefer modern authenticated encryption where available, do not use legacy ciphers for new protocols, and avoid reusing keys or IVs.
