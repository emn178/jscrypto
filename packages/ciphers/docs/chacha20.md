# ChaCha20

ChaCha20 family stream cipher and AEAD components for `@jscrypto/core`.

This module exports:

- `ChaCha20` and `XChaCha20` stream ciphers.
- `ChaCha20-Poly1305` and `XChaCha20-Poly1305` AEAD components.
- `chacha20Preset` for registering the full ChaCha20 family.

Poly1305 is a MAC, not a mode. This module does not support arbitrary `cipher + mac`
composition such as `createCipher({ cipher: 'ChaCha20', mac: 'Poly1305' })`.
Use the named AEAD components with `createAead` instead.

Use ChaCha20-Poly1305 or XChaCha20-Poly1305 for authenticated encryption. Raw
ChaCha20 only encrypts bytes and does not detect tampering.

Never reuse a nonce with the same key for ChaCha20-Poly1305 or XChaCha20-Poly1305.

## Usage

```ts
import { createRegistry } from '@jscrypto/core';
import { chacha20Preset } from '@jscrypto/ciphers/chacha20';

const registry = createRegistry().use(chacha20Preset);

const aead = registry.createAead({
  algorithm: 'ChaCha20-Poly1305',
  key,
});

const sealed = aead.seal(plaintext, {
  nonce,
  aad,
});

const opened = aead.open(sealed, {
  nonce,
  aad,
});

const sealer = aead.createSealer({ nonce, aad });
sealer.process(plaintextChunk);
const sealedChunks = sealer.finalize(lastPlaintextChunk);
```

Encryption returns ciphertext with a 16-byte authentication tag appended.
Decryption also accepts a detached tag:

```ts
const opened = aead.open(ciphertext, {
  nonce,
  aad,
  tag,
});
```

Raw unauthenticated ChaCha20 remains available through `createCipher`:

```ts
const cipher = registry.createCipher({
  cipher: 'ChaCha20',
  key,
  nonce,
});
```

## Components

| Export | Registry name | Kind | Key bytes | Nonce bytes | Options |
| --- | --- | --- | --- | --- | --- |
| `chacha20` | `ChaCha20` | Stream cipher | 32 | 12 | `nonce`, `counter?: number` |
| `xchacha20` | `XChaCha20` | Stream cipher | 32 | 24 | `nonce`, `counter?: number` |
| `chacha20Poly1305` | `ChaCha20-Poly1305` | AEAD | 32 | 12 | `nonce`, `aad?: Uint8Array`, `tag?: Uint8Array` on open |
| `xchacha20Poly1305` | `XChaCha20-Poly1305` | AEAD | 32 | 24 | `nonce`, `aad?: Uint8Array`, `tag?: Uint8Array` on open |

AEAD components support one-shot `seal` / `open` and primitive transform
creation with `createSealer` / `createOpener`. The current ChaCha20-Poly1305
implementation is backed by a one-shot primitive, so AEAD transforms buffer and
emit from `finalize()`. Raw `ChaCha20` and `XChaCha20` remain true streaming
transforms with `process` / `finalize`.

## Browser Files

| Export path | File |
| --- | --- |
| `@jscrypto/ciphers/chacha20/browser` | `dist/jscrypto-ciphers-chacha20.iife.min.js` |
| `@jscrypto/ciphers/chacha20/umd` | `dist/jscrypto-ciphers-chacha20.umd.min.js` |
