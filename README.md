# @jscrypto
[![CI](https://github.com/emn178/jscrypto/actions/workflows/ci.yml/badge.svg)](https://github.com/emn178/jscrypto/actions/workflows/ci.yml)
[![Coverage Status](https://coveralls.io/repos/emn178/jscrypto/badge.svg?branch=main)](https://coveralls.io/r/emn178/jscrypto?branch=main)
[![NPM](https://nodei.co/npm/@jscrypto/core.png?style=flat&data=n,v,d&color=brightgreen)](https://www.npmjs.com/package/@jscrypto/core)
[![NPM](https://nodei.co/npm/@jscrypto/classic.png?style=flat&data=n,v,d&color=brightgreen)](https://www.npmjs.com/package/@jscrypto/classic)

Composable cryptography components for JavaScript and TypeScript.

`@jscrypto` is a small Uint8Array-first framework for wiring ciphers, modes, paddings, KDFs, formats, hashes, and presets through one registry. The first release focuses on classic cipher/KDF/format behavior and is implemented without a runtime dependency on other crypto frameworks.

This project is not affiliated with Node.js `crypto`, the Web Crypto API, or npm.

## Packages

- `@jscrypto/core`: registry, component contracts, transform helpers, byte helpers, and shared errors.
- `@jscrypto/classic`: AES, DES, Triple DES, RC4, RC4Drop, CBC, CFB, CTR, OFB, ECB, GCM, classic paddings, PBKDF2, EvpKDF, and OpenSSL `Salted__` formatting.
- `@jscrypto/classic/hashes`: opt-in hash preset (`classicHashesPreset`) for KDF/derived-key flows.

The public package count is intentionally small. `@jscrypto/classic` still keeps internal modules split by cipher, mode, padding, KDF, format, hash, and preset so those boundaries stay testable and can be split later if the need becomes real.

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

`createCipher(...)` returns a reusable facade. The key and selected algorithm stay on the facade; per-message material such as IV, nonce, AAD, and authentication tag is passed to `encrypt`, `decrypt`, `createEncryptor`, or `createDecryptor`.

## Streaming

```ts
import { concatBytes, randomBytes } from '@jscrypto/core';
import { registry } from '@jscrypto/classic';

const key = randomBytes(32);
const iv = randomBytes(16);

const cipher = registry.createCipher({
  cipher: 'AES',
  mode: 'CBC',
  padding: 'Pkcs7',
  key,
});

const encryptor = cipher.createEncryptor({ iv });
const ciphertext = concatBytes(
  encryptor.process(chunk1),
  encryptor.process(chunk2),
  encryptor.finalize(),
);

const decryptor = cipher.createDecryptor({ iv });
const plaintext = concatBytes(
  decryptor.process(ciphertext.subarray(0, 7)),
  decryptor.process(ciphertext.subarray(7)),
  decryptor.finalize(),
);
```

## Derived Keys

Derived-key ciphers derive key material through a KDF, then optionally split it into `key || iv` and wrap salt/ciphertext through a format component. `kdf.input` is the KDF input material: a password/passphrase for PBKDF2 and EvpKDF, IKM for future HKDF, or a shared secret for future X9.63 / ConcatKDF flows.

`registry.derive(...)` returns derived bytes only. It does not split key/IV.

```ts
import { randomBytes } from '@jscrypto/core';
import { registry } from '@jscrypto/classic';
import { classicHashesPreset } from '@jscrypto/classic/hashes';

registry.use(classicHashesPreset);

const salt = randomBytes(8);
const keyMaterial = registry.derive({
  name: 'PBKDF2',
  input: 'secret',
  salt,
  iterations: 10000,
  hash: 'SHA256',
  length: 32,
});
```

`createDerivedKeyCipher(...)` derives key material for a cipher facade. With `ivSize > 0`, it derives `key || iv` and splits internally.

Explicit key/IV sizes, for example AES-128-CBC:

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

Using cipher defaults, which select AES-256-CBC:

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
  // keySize defaults to AES's largest key size: 32 bytes.
  // ivSize defaults to AES's block size: 16 bytes.
  format: 'OpenSSL',
});
```

KDF salt can be supplied per operation through `{ salt }` or fixed on the facade through `kdf.salt`. On decrypt, OpenSSL format prefers the salt parsed from the `Salted__` header, so callers normally do not pass `{ salt }` again for OpenSSL ciphertext. Formats serialize or parse metadata; they do not generate salt in the new derived-key API.

If `keySize` is omitted, `createDerivedKeyCipher(...)` uses the selected cipher's largest declared key size. For AES this is 32 bytes. If `ivSize` is omitted, block ciphers use their block size and stream ciphers use 0. For AES-CBC this means the default derived material is 48 bytes: 32 bytes of key plus 16 bytes of IV.

The older `createPassphraseCipher(...)` API remains available as a deprecated compatibility wrapper. It preserves the previous passphrase/OpenSSL convenience behavior, including random salt generation when needed.

The derived-key API also supports streaming:

```ts
import { concatBytes, randomBytes } from '@jscrypto/core';

const salt = randomBytes(8);
const encryptor = cipher.createEncryptor({ salt });
const encrypted = concatBytes(
  encryptor.process(chunk1),
  encryptor.process(chunk2),
  encryptor.finalize(),
);
```

## Hash Compatibility

Built-in hashes are opt-in through `@jscrypto/classic/hashes`. `registry.use(classicHashesPreset)` registers MD5, SHA1, SHA224, SHA256, SHA384, SHA512, KECCAK512, deprecated SHA3, and RIPEMD160.

`SHA3` is kept as a deprecated legacy alias for Keccak-512. New code should use `KECCAK512`. If NIST SHA3-512 is added later, it should be registered under a separate explicit name.

## Stream Ciphers

Stream ciphers do not use mode, padding, or IV.

```ts
import { registry } from '@jscrypto/classic';

const key = new TextEncoder().encode('secret');
const cipher = registry.createCipher({
  cipher: 'RC4Drop',
  key,
  drop: 256,
});

const ciphertext = cipher.encrypt(plaintext);
```

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

const ciphertext = sealed.subarray(0, sealed.length - 16);
const tag = sealed.subarray(sealed.length - 16);
const detached = cipher.decrypt(ciphertext, { nonce, aad, tag });
```

## Custom Registry

The classic package exports a singleton `registry` for normal use and a factory when isolation is useful.

```ts
import { createRegistry } from '@jscrypto/core';
import { aes, cbc, pkcs7 } from '@jscrypto/classic';

const registry = createRegistry()
  .use(aes)
  .use(cbc)
  .use(pkcs7);
```

## Browser Builds

Both packages ship ESM, CommonJS, IIFE, and UMD outputs.
The classic browser bundle is not standalone; load `@jscrypto/core` first so extensions share the same registry contracts.

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

Load `@jscrypto/classic/dist/jscrypto-classic-hashes.iife.min.js` only when browser code uses KDFs that resolve classic hash components.

## Supported Classic Components

- Ciphers: AES, DES, Triple DES, RC4, RC4Drop.
- Modes: CBC, CFB, CTR, OFB, ECB, GCM.
- Paddings: Pkcs7, Iso97971, AnsiX923, Iso10126, ZeroPadding, NoPadding.
- KDFs: PBKDF2, EvpKDF.
- Formats: OpenSSL `Salted__`.

## Development

```sh
npm install
npm run build
npm test
npm run coverage
```

`npm run build` creates ESM, CommonJS, IIFE, and UMD bundles for each published package. `npm run coverage` writes text output and an HTML report under `coverage/`.

## Security

This first release includes classic algorithms for compatibility with existing data and tools. Prefer modern authenticated encryption where available, do not use legacy ciphers for new protocols, and avoid reusing keys or IVs.
