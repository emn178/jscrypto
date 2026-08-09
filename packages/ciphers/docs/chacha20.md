# ChaCha20

ChaCha20 family stream cipher and AEAD components for `@jscrypto/core`.

This module exports:

- `ChaCha20` and `XChaCha20` stream ciphers.
- `ChaCha20-Poly1305` and `XChaCha20-Poly1305` AEAD ciphers.
- `chacha20Preset` for registering the full ChaCha20 family.

Poly1305 is a MAC, not a mode. This module does not support arbitrary `cipher + mac`
composition such as `createCipher({ cipher: 'ChaCha20', mac: 'Poly1305' })`.
Use the named AEAD components instead.

Use ChaCha20-Poly1305 or XChaCha20-Poly1305 for authenticated encryption. Raw
ChaCha20 only encrypts bytes and does not detect tampering.

Never reuse a nonce with the same key for ChaCha20-Poly1305 or XChaCha20-Poly1305.

## Usage

```ts
import { createRegistry } from '@jscrypto/core';
import { chacha20Preset } from '@jscrypto/ciphers/chacha20';

const registry = createRegistry().use(chacha20Preset);

const cipher = registry.createCipher({
  cipher: 'ChaCha20-Poly1305',
  key,
});

const sealed = cipher.encrypt(plaintext, {
  nonce,
  aad,
});

const opened = cipher.decrypt(sealed, {
  nonce,
  aad,
});
```

Encryption returns ciphertext with a 16-byte authentication tag appended.
Decryption also accepts a detached tag:

```ts
const opened = cipher.decrypt(ciphertext, {
  nonce,
  aad,
  tag,
});
```

## Components

| Export | Registry name | Type | Key bytes | Nonce bytes | Options |
| --- | --- | --- | --- | --- | --- |
| `chacha20` | `ChaCha20` | Stream cipher | 32 | 12 | `nonce`, `counter?: number` |
| `xchacha20` | `XChaCha20` | Stream cipher | 32 | 24 | `nonce`, `counter?: number` |
| `chacha20Poly1305` | `ChaCha20-Poly1305` | AEAD | 32 | 12 | `nonce`, `aad?: Uint8Array`, `tag?: Uint8Array` on decrypt |
| `xchacha20Poly1305` | `XChaCha20-Poly1305` | AEAD | 32 | 24 | `nonce`, `aad?: Uint8Array`, `tag?: Uint8Array` on decrypt |

AEAD transforms accept chunked input, but output from `finalize()` because the
current implementation uses a one-shot AEAD primitive. Raw `ChaCha20` and
`XChaCha20` output from `process()`.

## Browser Files

| Export path | File |
| --- | --- |
| `@jscrypto/ciphers/chacha20/browser` | `dist/jscrypto-ciphers-chacha20.iife.min.js` |
| `@jscrypto/ciphers/chacha20/umd` | `dist/jscrypto-ciphers-chacha20.umd.min.js` |
