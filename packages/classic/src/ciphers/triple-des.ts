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

    encrypt(input, output) {
      assertBlocks(input, output);
      for (let offset = 0; offset < input.length; offset += 8) {
        encryptTripleBlock(input.subarray(offset, offset + 8), output.subarray(offset, offset + 8), first, second, third);
      }
      return output;
    },

    decrypt(input, output) {
      assertBlocks(input, output);
      for (let offset = 0; offset < input.length; offset += 8) {
        decryptTripleBlock(input.subarray(offset, offset + 8), output.subarray(offset, offset + 8), first, second, third);
      }
      return output;
    },
  };
}

function encryptTripleBlock(
  input: Uint8Array,
  output: Uint8Array,
  first: BlockCipher,
  second: BlockCipher,
  third: BlockCipher,
): void {
  const firstOutput = new Uint8Array(8);
  const secondOutput = new Uint8Array(8);
  first.encrypt(input, firstOutput);
  second.decrypt(firstOutput, secondOutput);
  third.encrypt(secondOutput, output);
}

function decryptTripleBlock(
  input: Uint8Array,
  output: Uint8Array,
  first: BlockCipher,
  second: BlockCipher,
  third: BlockCipher,
): void {
  const thirdOutput = new Uint8Array(8);
  const secondOutput = new Uint8Array(8);
  third.decrypt(input, thirdOutput);
  second.encrypt(thirdOutput, secondOutput);
  first.decrypt(secondOutput, output);
}

function assertBlocks(input: Uint8Array, output: Uint8Array): void {
  if (input.length % 8 !== 0) {
    throw new Error('Triple DES input length must be a multiple of 64 bits.');
  }
  if (output.length !== input.length) {
    throw new Error('Triple DES output length must equal input length.');
  }
}
