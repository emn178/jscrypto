# @jscrypto
[![CI](https://github.com/emn178/jscrypto/actions/workflows/ci.yml/badge.svg)](https://github.com/emn178/jscrypto/actions/workflows/ci.yml)
[![Coverage Status](https://coveralls.io/repos/emn178/jscrypto/badge.svg?branch=main)](https://coveralls.io/r/emn178/jscrypto?branch=main)

Composable cryptography components for JavaScript and TypeScript.

`@jscrypto` is a small Uint8Array-first framework for wiring ciphers, modes, paddings, KDFs, formats, hashes, and presets through one registry.

This project is not affiliated with Node.js `crypto`, the Web Crypto API, or npm.

## Packages

| Package | Description |
| --- | --- |
| [`@jscrypto/core`](https://github.com/emn178/jscrypto/tree/main/packages/core) | Registry, component contracts, transform helpers, byte helpers, and shared errors. |
| [`@jscrypto/classic`](https://github.com/emn178/jscrypto/tree/main/packages/classic) | AES, DES, Triple DES, RC4, RC4Drop, CBC, CFB, CTR, OFB, ECB, GCM, classic paddings, PBKDF2, EvpKDF, hashes, and OpenSSL `Salted__` formatting. |
| [`@jscrypto/chacha20`](https://github.com/emn178/jscrypto-chacha20) | ChaCha20 block cipher components for `@jscrypto/core` registries. |
| [`@jscrypto/speck`](https://github.com/emn178/jscrypto-speck) | SPECK block cipher components for `@jscrypto/core` registries. |
| [`@jscrypto/hkdf`](https://github.com/emn178/jscrypto-hkdf) | RFC 5869 HKDF, HKDF-Extract, and HKDF-Expand KDF components. |

The public package count is intentionally small. `@jscrypto/classic` still keeps internal modules split by cipher, mode, padding, KDF, format, hash, and preset so those boundaries stay testable and can be split later if the need becomes real.

## Demo
[AES Encrypt Online](https://emn178.github.io/online-tools/aes/encrypt/)  
[AES Decrypt Online](https://emn178.github.io/online-tools/aes/decrypt/)  
[DES Encrypt Online](https://emn178.github.io/online-tools/des/encrypt/)  
[DES Decrypt Online](https://emn178.github.io/online-tools/des/decrypt/)  
[Triple DES Encrypt Online](https://emn178.github.io/online-tools/triple-des/encrypt/)  
[Triple DES Decrypt Online](https://emn178.github.io/online-tools/triple-des/decrypt/)  
[RC4 Encrypt Online](https://emn178.github.io/online-tools/rc4/encrypt/)  
[RC4 Decrypt Online](https://emn178.github.io/online-tools/rc4/decrypt/)  
[PBKDF2 Online](https://emn178.github.io/online-tools/kdf/pbkdf2/)  
[EvpKDF Online](https://emn178.github.io/online-tools/kdf/evpkdf/)

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

For performance-sensitive paths, `mutableInput: true` lets modes reuse caller-owned input buffers when safe. Treat input passed with this option as consumed.

```ts
const mutable = plaintext.slice();
const ciphertext = cipher.encrypt(mutable, { iv, mutableInput: true });
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

`createDerivedKeyCipher(...)` derives key material for a cipher facade. The selected mode decides whether IV material is also derived. CBC/CFB/CTR/OFB derive a block-size IV, ECB and GCM derive key material only, and stream ciphers derive key material only.

Explicit key size, for example AES-128-CBC:

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
  // CBC derives a 16-byte IV from AES's block size.
  format: 'OpenSSL',
});
```

KDF salt can be supplied per operation through `{ salt }` or fixed on the facade through `kdf.salt`. On decrypt, OpenSSL format prefers the salt parsed from the `Salted__` header, so callers normally do not pass `{ salt }` again for OpenSSL ciphertext. Formats serialize or parse metadata; they do not generate salt in the new derived-key API.

If `keySize` is omitted, `createDerivedKeyCipher(...)` uses the selected cipher's largest declared key size. For AES this is 32 bytes. The selected mode contributes any derived IV length. For AES-CBC this means the default derived material is 48 bytes: 32 bytes of key plus 16 bytes of IV. AES-GCM derives key material only; pass a fresh nonce per operation.

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

Built-in hashes are opt-in through `@jscrypto/classic/hashes`. `registry.use(classicHashesPreset)` registers MD5, SHA1, SHA224, SHA256, SHA384, SHA512, KECCAK512, and RIPEMD160.

`KECCAK512` is Keccak-512. NIST SHA3-512 is not included yet and should use a distinct name if added later.

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

const sealed = cipher.encrypt(plaintext, { nonce, aad });
const decrypted = cipher.decrypt(sealed, { nonce, aad });

const ciphertext = sealed.subarray(0, sealed.length - 16);
const tag = sealed.subarray(sealed.length - 16);
const detached = cipher.decrypt(ciphertext, { nonce, aad, tag });

// The default appended tag length is 16 bytes. If you choose a different
// appended tag length, pass the same value during decrypt.
const shortTagSealed = cipher.encrypt(plaintext, { nonce, aad, tagLength: 12 });
const shortTagDecrypted = cipher.decrypt(shortTagSealed, { nonce, aad, tagLength: 12 });
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
