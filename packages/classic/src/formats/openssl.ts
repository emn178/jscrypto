import type { FormatComponent } from '@crypto/core';
import { concatBytes, equalBytes } from '@crypto/core';

export const OPENSSL_SALTED_MAGIC = new Uint8Array([
  0x53, 0x61, 0x6c, 0x74, 0x65, 0x64, 0x5f, 0x5f,
]);

export const opensslFormat: FormatComponent<'OpenSSL'> = {
  kind: 'format',
  name: 'OpenSSL',
  mediaType: 'application/octet-stream',
  stringify({ ciphertext, salt }) {
    if (!salt) {
      return ciphertext.slice();
    }
    assertSalt(salt);
    return concatBytes(OPENSSL_SALTED_MAGIC, salt, ciphertext);
  },
  parse(input) {
    if (!hasSaltHeader(input)) {
      return { ciphertext: input.slice() };
    }

    return {
      salt: input.slice(OPENSSL_SALTED_MAGIC.length, OPENSSL_SALTED_MAGIC.length + 8),
      ciphertext: input.slice(OPENSSL_SALTED_MAGIC.length + 8),
    };
  },
};

function hasSaltHeader(input: Uint8Array): boolean {
  return input.length >= 16 && equalBytes(input.subarray(0, OPENSSL_SALTED_MAGIC.length), OPENSSL_SALTED_MAGIC);
}

function assertSalt(salt: Uint8Array): void {
  if (salt.length !== 8) {
    throw new Error('OpenSSL salt must be 64 bits.');
  }
}
