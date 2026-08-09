# RC4 And RC4Drop

RC4 stream cipher components for compatibility with legacy data.

RC4 and RC4Drop are not recommended for new cryptographic designs. RC4Drop uses a
default byte drop of 192 bytes and also accepts an explicit `drop` option.

## Usage

```ts
import { createRegistry } from '@jscrypto/core';
import { rc4Preset } from '@jscrypto/ciphers/rc4';

const registry = createRegistry().use(rc4Preset);
```

## Components

| Export | Registry name | Type | Options |
| --- | --- | --- | --- |
| `rc4` | `RC4` | Stream cipher | `drop?: number`, default `0` |
| `rc4Drop` | `RC4Drop` | Stream cipher | `drop?: number`, default `192` |

## Browser Files

| Export path | File |
| --- | --- |
| `@jscrypto/ciphers/rc4/browser` | `dist/jscrypto-ciphers-rc4.iife.min.js` |
| `@jscrypto/ciphers/rc4/umd` | `dist/jscrypto-ciphers-rc4.umd.min.js` |
