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
  const firstOutput = new Uint8Array(8);
  const secondOutput = new Uint8Array(8);

  return {
    blockSize: 8,

    encryptBlock(input, inputOffset, output, outputOffset) {
      encryptTripleBlockAt(input, inputOffset, output, outputOffset, first, second, third, firstOutput, secondOutput);
    },

    decryptBlock(input, inputOffset, output, outputOffset) {
      decryptTripleBlockAt(input, inputOffset, output, outputOffset, first, second, third, firstOutput, secondOutput);
    },

    encrypt(input, output) {
      assertBlocks(input, output);
      for (let offset = 0; offset < input.length; offset += 8) {
        encryptTripleBlockAt(input, offset, output, offset, first, second, third, firstOutput, secondOutput);
      }
      return output;
    },

    decrypt(input, output) {
      assertBlocks(input, output);
      for (let offset = 0; offset < input.length; offset += 8) {
        decryptTripleBlockAt(input, offset, output, offset, first, second, third, firstOutput, secondOutput);
      }
      return output;
    },
  };
}

function encryptTripleBlockAt(
  input: Uint8Array,
  inputOffset: number,
  output: Uint8Array,
  outputOffset: number,
  first: BlockCipher,
  second: BlockCipher,
  third: BlockCipher,
  firstOutput: Uint8Array,
  secondOutput: Uint8Array,
): void {
  encryptBlock(first, input, inputOffset, firstOutput, 0);
  decryptBlock(second, firstOutput, 0, secondOutput, 0);
  encryptBlock(third, secondOutput, 0, output, outputOffset);
}

function decryptTripleBlockAt(
  input: Uint8Array,
  inputOffset: number,
  output: Uint8Array,
  outputOffset: number,
  first: BlockCipher,
  second: BlockCipher,
  third: BlockCipher,
  thirdOutput: Uint8Array,
  secondOutput: Uint8Array,
): void {
  decryptBlock(third, input, inputOffset, thirdOutput, 0);
  encryptBlock(second, thirdOutput, 0, secondOutput, 0);
  decryptBlock(first, secondOutput, 0, output, outputOffset);
}

function encryptBlock(
  cipher: BlockCipher,
  input: Uint8Array,
  inputOffset: number,
  output: Uint8Array,
  outputOffset: number,
): void {
  if (cipher.encryptBlock) {
    cipher.encryptBlock(input, inputOffset, output, outputOffset);
  } else {
    cipher.encrypt(input.subarray(inputOffset, inputOffset + 8), output.subarray(outputOffset, outputOffset + 8));
  }
}

function decryptBlock(
  cipher: BlockCipher,
  input: Uint8Array,
  inputOffset: number,
  output: Uint8Array,
  outputOffset: number,
): void {
  if (cipher.decryptBlock) {
    cipher.decryptBlock(input, inputOffset, output, outputOffset);
  } else {
    cipher.decrypt(input.subarray(inputOffset, inputOffset + 8), output.subarray(outputOffset, outputOffset + 8));
  }
}

function assertBlocks(input: Uint8Array, output: Uint8Array): void {
  if (input.length % 8 !== 0) {
    throw new Error('Triple DES input length must be a multiple of 64 bits.');
  }
  if (output.length !== input.length) {
    throw new Error('Triple DES output length must equal input length.');
  }
}
