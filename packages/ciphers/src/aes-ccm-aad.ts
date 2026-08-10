import { concatBytes } from '@jscrypto/core';

const AAD_SHORT_LIMIT = 0xff00;

export function encodeCcmAad(aad: Uint8Array): Uint8Array {
  return concatBytes(encodeCcmAadLength(aad.length), aad);
}

/**
 * Encode only the CCM AAD length prefix for a given length.
 * Accepts synthetic lengths so the `0xffff` form (>= 2^32) can be unit-tested
 * without allocating multi-gigabyte AAD buffers.
 */
export function encodeCcmAadLength(aadLength: number): Uint8Array {
  if (aadLength === 0) {
    return new Uint8Array(0);
  }

  if (aadLength < AAD_SHORT_LIMIT) {
    const encoded = new Uint8Array(2);
    encoded[0] = (aadLength >>> 8) & 0xff;
    encoded[1] = aadLength & 0xff;
    return encoded;
  }

  if (aadLength < 0x100000000) {
    const encoded = new Uint8Array(6);
    encoded[0] = 0xff;
    encoded[1] = 0xfe;
    encoded[2] = (aadLength >>> 24) & 0xff;
    encoded[3] = (aadLength >>> 16) & 0xff;
    encoded[4] = (aadLength >>> 8) & 0xff;
    encoded[5] = aadLength & 0xff;
    return encoded;
  }

  const encoded = new Uint8Array(10);
  encoded[0] = 0xff;
  encoded[1] = 0xff;
  let remaining = aadLength;
  for (let i = 9; i >= 2; i--) {
    encoded[i] = remaining % 256;
    remaining = Math.floor(remaining / 256);
  }
  return encoded;
}
