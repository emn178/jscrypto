# @jscrypto
[![CI](https://github.com/emn178/jscrypto/actions/workflows/ci.yml/badge.svg)](https://github.com/emn178/jscrypto/actions/workflows/ci.yml)
[![Coverage Status](https://coveralls.io/repos/emn178/jscrypto/badge.svg?branch=main)](https://coveralls.io/r/emn178/jscrypto?branch=main)

Composable cryptography components for JavaScript and TypeScript.

`@jscrypto` is a small Uint8Array-first framework for wiring ciphers, modes, paddings, KDFs, formats, hashes, and presets through one registry. The first release focuses on classic cipher/KDF/format behavior and is implemented without a runtime dependency on other crypto frameworks.

This project is not affiliated with Node.js `crypto`, the Web Crypto API, or npm.

## Packages

- `@jscrypto/core`: registry, component contracts, transform helpers, byte helpers, and shared errors.
- `@jscrypto/classic`: AES, DES, Triple DES, RC4, RC4Drop, CBC, CFB, CTR, OFB, ECB, GCM, classic paddings, PBKDF2, EvpKDF, and OpenSSL `Salted__` formatting.
- `@jscrypto/classic/hashes`: opt-in hash components (`registerClassicHashes`) for KDF/derived-key flows.

The public package count is intentionally small. `@jscrypto/classic` still keeps internal modules split by cipher, mode, padding, KDF, format, hash, and preset so those boundaries stay testable and can be split later if the need becomes real.

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

`createCipher` returns a reusable facade. Each `encrypt` or `decrypt` call creates a fresh transform internally, so the facade can be reused safely for multiple one-shot calls.

## Streaming

```ts
import { concatBytes } from '@jscrypto/core';
import { registry } from '@jscrypto/classic';

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

## Derived Keys

Derived-key ciphers derive key and IV through a KDF, then optionally wrap salt and ciphertext through a format component. `kdf.input` is the KDF input material: a password/passphrase for PBKDF2 and EvpKDF, IKM for future HKDF, or a shared secret for future X9.63 / ConcatKDF flows.

`registry.derive(...)` returns derived bytes only. It does not split key/IV.

```ts
import { registry } from '@jscrypto/classic';
import { registerClassicHashes } from '@jscrypto/classic/hashes';

registerClassicHashes(registry);

const keyMaterial = registry.derive({
  name: 'PBKDF2',
  input: 'secret',
  salt,
  iterations: 10000,
  hash: 'SHA256',
  length: 48,
});

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

`createDerivedKeyCipher(...)` derives `key || iv` and splits internally. The older `createPassphraseCipher(...)` API remains available as a deprecated compatibility wrapper.

The derived-key API also supports streaming:

```ts
import { concatBytes } from '@jscrypto/core';

const encryptor = cipher.createEncryptor();
const encrypted = concatBytes(
  encryptor.process(chunk1),
  encryptor.process(chunk2),
  encryptor.finalize(),
);
```

## Hash Compatibility

Built-in hashes are opt-in through `@jscrypto/classic/hashes`. `registerClassicHashes(registry)` registers MD5, SHA1, SHA224, SHA256, SHA384, SHA512, KECCAK512, deprecated SHA3, and RIPEMD160.

`SHA3` is kept as a deprecated legacy alias for Keccak-512. New code should use `KECCAK512`. If NIST SHA3-512 is added later, it should be registered under a separate explicit name.

## Stream Ciphers

Stream ciphers do not use mode, padding, or IV.

```ts
import { registry } from '@jscrypto/classic';

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

const ciphertext = sealed.subarray(0, sealed.length - 16);
const tag = sealed.subarray(sealed.length - 16);
const detached = registry.createCipher({
  cipher: 'AES',
  mode: 'GCM',
  key,
  iv: nonce,
  aad,
  tag,
}).decrypt(ciphertext);
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

```ts
import { createRegistry } from '@jscrypto/core';
import { registry } from '@jscrypto/classic';
```

```html
<script src="node_modules/@jscrypto/core/dist/jscrypto-core.iife.min.js"></script>
<script src="node_modules/@jscrypto/classic/dist/jscrypto-classic.iife.min.js"></script>
<!-- Required only for built-in KDF hash implementations. -->
<script src="node_modules/@jscrypto/classic/dist/jscrypto-classic-hashes.iife.min.js"></script>
<script>
  jscryptoClassicHashes.registerClassicHashes(jscryptoClassic.registry);
  const cipher = jscryptoClassic.registry.createCipher({
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
