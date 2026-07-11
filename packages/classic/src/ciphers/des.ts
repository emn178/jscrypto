import { createCryptoJsBlockCipher, CryptoJS } from '../adapter/crypto-js.js';
import type { BlockCipher, CipherComponent } from '@crypto/core';

export const des: CipherComponent<'DES'> = {
  kind: 'cipher',
  name: 'DES',
  type: 'block',
  blockSize: 8,
  keySizes: [8],
  create(key) {
    return createDesCipher(key);
  },
};

export function createDesCipher(key: Uint8Array): BlockCipher {
  if (key.length !== 8) {
    throw new Error('DES key must be 64 bits.');
  }

  return createCryptoJsBlockCipher({
    name: 'DES',
    key,
    blockSize: 8,
    algorithm: CryptoJS.algo.DES,
  });
}
