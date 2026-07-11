import { createCryptoJsBlockCipher, CryptoJS } from '../adapter/crypto-js.js';
import type { BlockCipher, CipherComponent } from '@crypto/core';

export const aes: CipherComponent<'AES'> = {
  kind: 'cipher',
  name: 'AES',
  type: 'block',
  blockSize: 16,
  keySizes: [16, 24, 32],
  create(key) {
    return createAesCipher(key);
  },
};

export function createAesCipher(key: Uint8Array): BlockCipher {
  if (![16, 24, 32].includes(key.length)) {
    throw new Error('AES key must be 128, 192, or 256 bits.');
  }

  return createCryptoJsBlockCipher({
    name: 'AES',
    key,
    blockSize: 16,
    algorithm: CryptoJS.algo.AES,
  });
}
