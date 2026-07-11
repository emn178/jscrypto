# @crypto

Composable cryptography components for JavaScript and TypeScript.

This repository is a monorepo for the `@crypto/*` npm packages. The goal is a small, Uint8Array-first framework where ciphers, modes, paddings, KDFs, formats, and presets can be implemented and published independently.

This project is not affiliated with Node.js `crypto`, the Web Crypto API, or npm.

## Packages

- `@crypto/core`: shared types, registry, byte helpers, and errors.
- `@crypto/classic`: online-tools-compatible classic components, including AES, DES, Triple DES, RC4, RC4Drop, CBC, CFB, CTR, OFB, ECB, current classic paddings, PBKDF2, EvpKDF, and OpenSSL `Salted__` formatting.

The public package count is intentionally small. `@crypto/classic` still keeps separate internal modules for ciphers, modes, paddings, KDFs, formats, adapters, and presets so those boundaries stay testable and can be split later if a real need appears.

The first working slices are AES/DES/Triple DES + CBC/ECB/CFB/CTR/OFB + all current online-tools paddings, RC4/RC4Drop stream ciphers, PBKDF2/EvpKDF, and OpenSSL `Salted__` formatting. GCM is still next-step work.

## First Target

The first implementation target is parity with the CryptoJS-backed features already used by online-tools:

- Ciphers: AES, DES, Triple DES, RC4, RC4Drop.
- Modes: CBC, CFB, CTR, OFB, ECB.
- Paddings: Pkcs7, Iso97971, AnsiX923, Iso10126, ZeroPadding, NoPadding.
- KDFs: PBKDF2, EvpKDF.
- Formats: OpenSSL `Salted__` and raw bytes.

AES-GCM is still planned, but it should come after the current online-tools surface is represented cleanly.

## Shape

```ts
import { concatBytes } from '@crypto/core';
import { registry } from '@crypto/classic';

const cipher = registry.createCipher({
  cipher: 'AES',
  mode: 'CBC',
  padding: 'NoPadding',
  key,
  iv,
});

const oneShotCiphertext = cipher.encrypt(plaintext);

const encryptor = cipher.createEncryptor();
const ciphertext = concatBytes(
  encryptor.process(chunk1),
  encryptor.process(chunk2),
  encryptor.finalize(),
);
```

Stream ciphers do not use mode, padding, or IV:

```ts
import { createRegistry } from '@crypto/core';
import { rc4 } from '@crypto/classic';

const cipher = createRegistry().use(rc4).createCipher({
  cipher: 'RC4',
  key,
  drop: 256,
});

const ciphertext = cipher.encrypt(plaintext);
```

Passphrase-based encryption derives key and IV, then optionally wraps the salt and ciphertext using a format component:

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

Compatibility requirements from online-tools, such as CryptoJS/OpenSSL output formats and EvpKDF, should be added as separate components rather than baked into the core.
