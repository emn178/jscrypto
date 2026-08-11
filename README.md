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
| [`@jscrypto/ciphers`](https://github.com/emn178/jscrypto/tree/main/packages/ciphers) | AES, DES, Triple DES, RC4, RC4Drop, SPECK, ChaCha20, XChaCha20, plus AEAD components AES-GCM, ChaCha20-Poly1305, and XChaCha20-Poly1305. |
| [`@jscrypto/modes`](https://github.com/emn178/jscrypto/tree/main/packages/modes) | CBC, CFB, CTR, OFB, ECB, and compatibility GCM mode components. |
| [`@jscrypto/paddings`](https://github.com/emn178/jscrypto/tree/main/packages/paddings) | Pkcs7, Pkcs5 compatibility alias, Iso97971, AnsiX923, Iso10126, ZeroPadding, and NoPadding components. |
| [`@jscrypto/kdfs`](https://github.com/emn178/jscrypto/tree/main/packages/kdfs) | PBKDF2, EvpKDF, HKDF, HKDF-Extract, HKDF-Expand, Scrypt, and Argon2 KDF components. |
| [`@jscrypto/formats`](https://github.com/emn178/jscrypto/tree/main/packages/formats) | OpenSSL `Salted__` format components. |
| [`@jscrypto/hashes`](https://github.com/emn178/jscrypto/tree/main/packages/hashes) | MD5, SHA1, SHA224, SHA256, SHA384, SHA512, KECCAK512, and RIPEMD160 hash components. |
| [`@jscrypto/suite`](https://github.com/emn178/jscrypto/tree/main/packages/suite) | Convenience basic and all registries for official component packages. |

The main repository is organized by component type. Use `@jscrypto/suite` for a ready-to-use basic registry, `@jscrypto/suite/all` for all built-in compatibility components, or import individual components from packages such as `@jscrypto/ciphers/aes` and `@jscrypto/modes/cbc`.

`@jscrypto/classic` was removed in v0.10.0. Use `@jscrypto/suite` for convenience registries or component packages for focused imports.

## Install

```sh
npm install @jscrypto/core @jscrypto/suite
```

## Quick Start

```ts
import { randomBytes } from '@jscrypto/core';
import { registry } from '@jscrypto/suite';

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

Authenticated encryption uses `createAead(...)` instead of the traditional cipher + mode pipeline:

```ts
import { randomBytes } from '@jscrypto/core';
import { registry } from '@jscrypto/suite';

const key = randomBytes(32);
const nonce = randomBytes(12);

const aead = registry.createAead({
  algorithm: 'AES-GCM',
  key,
});

const sealed = aead.seal(plaintext, { nonce, aad });
const opened = aead.open(sealed, { nonce, aad });
```

`seal()` appends the authentication tag. `open()` accepts that sealed byte string or a detached `tag`. AEAD has no padding, and `nonce` must be unique for a given key.

## Streaming

```ts
import { concatBytes, randomBytes } from '@jscrypto/core';
import { registry } from '@jscrypto/suite';

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

Derived-key ciphers derive key material through a KDF, then optionally split it into `key || iv` and wrap salt/ciphertext through a format component. `kdf.input` is the KDF input material: a password/passphrase for PBKDF2 and EvpKDF, IKM for HKDF, or a shared secret for future X9.63 / ConcatKDF flows.

`registry.derive(...)` returns derived bytes only. It does not split key/IV.

```ts
import { randomBytes } from '@jscrypto/core';
import { registry } from '@jscrypto/suite';

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
import { registry } from '@jscrypto/suite';

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

`createDerivedKeyAead(...)` is the AEAD equivalent. It derives the AEAD key only; nonce, AAD, detached tag, and tag length remain per-operation AEAD options.

```ts
import { randomBytes } from '@jscrypto/core';
import { registry } from '@jscrypto/suite';

const salt = randomBytes(8);
const nonce = randomBytes(12);
const aead = registry.createDerivedKeyAead({
  algorithm: 'AES-GCM',
  kdf: {
    name: 'PBKDF2',
    input: 'secret',
    salt,
    iterations: 100000,
    hash: 'SHA256',
  },
  keySize: 16,
});

const sealed = aead.seal(plaintext, { nonce });
const opened = aead.open(sealed, { nonce });
```

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

Built-in hashes are provided by `@jscrypto/hashes`. `registry.use(hashesPreset)` registers MD5, SHA1, SHA224, SHA256, SHA384, SHA512, KECCAK512, and RIPEMD160. `@jscrypto/suite` registers these hashes for you.

`KECCAK512` is Keccak-512. NIST SHA3-512 is not included yet and should use a distinct name if added later.

## Stream Ciphers

Stream ciphers do not use mode, padding, or IV.

```ts
import { registry } from '@jscrypto/suite';

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
import { registry } from '@jscrypto/suite';

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

`@jscrypto/suite` exports a singleton `registry` using the basic preset for normal use. Use `@jscrypto/suite/all` when DES, Triple DES, RC4, EvpKDF, or the full classic padding set is needed. Use `@jscrypto/core` and component packages when isolation or a smaller component set is useful.

```ts
import { createRegistry } from '@jscrypto/core';
import { aes } from '@jscrypto/ciphers/aes';
import { cbc } from '@jscrypto/modes/cbc';
import { pkcs7 } from '@jscrypto/paddings/pkcs7';

const registry = createRegistry()
  .use(aes)
  .use(cbc)
  .use(pkcs7);
```

## Browser Builds

Packages ship ESM, CommonJS, IIFE, and UMD outputs.
Browser bundles are not standalone; load `@jscrypto/core` first so extensions share the same registry contracts.

```html
<script src="node_modules/@jscrypto/core/dist/jscrypto-core.iife.min.js"></script>
<script src="node_modules/@jscrypto/suite/dist/jscrypto-suite.iife.min.js"></script>
<script>
  const key = jscryptoCore.randomBytes(32);
  const iv = jscryptoCore.randomBytes(16);
  const cipher = jscryptoSuite.registry.createCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    key,
  });
  const ciphertext = cipher.encrypt(plaintext, { iv });
</script>
```

The default suite bundle follows `basicPreset`. For explicit browser bundle sizes, use:

```html
<script src="node_modules/@jscrypto/core/dist/jscrypto-core.iife.min.js"></script>
<script src="node_modules/@jscrypto/suite/dist/jscrypto-suite-basic.iife.min.js"></script>
```

or load all bundled compatibility components:

```html
<script src="node_modules/@jscrypto/core/dist/jscrypto-core.iife.min.js"></script>
<script src="node_modules/@jscrypto/suite/dist/jscrypto-suite-all.iife.min.js"></script>
```

Load `@jscrypto/hashes/dist/jscrypto-hashes.iife.min.js` only when browser code uses KDFs that resolve hash components outside `@jscrypto/suite`.

Size-sensitive browser pages can combine the basic suite with focused component
bundles instead of loading a whole component package:

```html
<script src="node_modules/@jscrypto/core/dist/jscrypto-core.iife.min.js"></script>
<script src="node_modules/@jscrypto/suite/dist/jscrypto-suite-basic.iife.min.js"></script>
<script src="node_modules/@jscrypto/ciphers/dist/jscrypto-ciphers-chacha20.iife.min.js"></script>
<script>
  jscryptoSuiteBasic.registry.use(jscryptoCiphersChacha20.chacha20Preset);
</script>
```

## Supported Components

- Basic suite: AES and AES-GCM AEAD; CBC, CFB, CTR, OFB, ECB, compatibility GCM; Pkcs7 and NoPadding; PBKDF2 and HKDF; OpenSSL `Salted__`; bundled hashes.
- All suite: all component-package presets below.
- Ciphers: AES, DES, Triple DES, RC4, RC4Drop, SPECK, ChaCha20, XChaCha20.
- AEAD: AES-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305.
- Modes: CBC, CFB, CTR, OFB, ECB, compatibility GCM.
- Paddings: Pkcs7, Iso97971, AnsiX923, Iso10126, ZeroPadding, NoPadding.
- KDFs: PBKDF2, EvpKDF, HKDF, HKDF-Extract, HKDF-Expand.
- Formats: OpenSSL `Salted__`.

## Development

```sh
npm install
npm run test:src
npm run build
npm run test:dist
npm run coverage
```

- `npm run test:src` runs package-local TypeScript tests against source via `tsx` (no build required; needs Node.js >= 18.19).
- `npm run test:dist` runs root build/export/browser smoke tests under `tests/builds` and packaging integration under `tests/integration` against built artifacts.
- `npm run coverage` runs full source coverage (`coverage:src`).
- `npm run build` creates ESM, CommonJS, IIFE, and UMD bundles for each published package.

## Security

This first release includes classic algorithms for compatibility with existing data and tools. Prefer modern authenticated encryption where available, do not use legacy ciphers for new protocols, and avoid reusing keys or IVs.
