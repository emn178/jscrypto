import type { BlockCipher, CipherComponent } from '@jscrypto/core';
import { createDesCipher } from './des.js';

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
  if (key.length !== 16 && key.length !== 24) {
    throw new Error('Triple DES key must be 128 or 192 bits.');
  }

  const first = createDesCipher(key.subarray(0, 8));
  const second = createDesCipher(key.subarray(8, 16));
  const third = createDesCipher(key.length === 24 ? key.subarray(16, 24) : key.subarray(0, 8));

  return {
    blockSize: 8,

    encryptBlock(block) {
      assertBlock(block);
      return third.encryptBlock(second.decryptBlock(first.encryptBlock(block)));
    },

    decryptBlock(block) {
      assertBlock(block);
      return first.decryptBlock(second.encryptBlock(third.decryptBlock(block)));
    },
  };
}

function assertBlock(block: Uint8Array): void {
  if (block.length !== 8) {
    throw new Error('Triple DES block must be 64 bits.');
  }
}
