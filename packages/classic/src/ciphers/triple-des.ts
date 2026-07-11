import { createCryptoJsBlockCipher, CryptoJS } from '../adapter/crypto-js.js';
import type { BlockCipher, CipherComponent } from '@jscrypto/core';

export const tripleDes: CipherComponent<'TripleDES'> = {
  kind: 'cipher',
  name: 'TripleDES',
  type: 'block',
  blockSize: 8,
  keySizes: [16, 24],
  create(key) {
    return createTripleDesCipher(key);
  },
};

export function createTripleDesCipher(key: Uint8Array): BlockCipher {
  if (![16, 24].includes(key.length)) {
    throw new Error('Triple DES key must be 128 or 192 bits.');
  }

  return createCryptoJsBlockCipher({
    name: 'Triple DES',
    key,
    blockSize: 8,
    algorithm: CryptoJS.algo.TripleDES,
  });
}
