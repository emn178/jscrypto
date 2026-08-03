import type { BlockCipher, CipherComponent } from '@jscrypto/core';
import { unsafe as nobleAesUnsafe } from '@noble/ciphers/aes.js';

const BLOCK_SIZE = 16;

export const aes: CipherComponent<'AES'> = {
  kind: 'cipher',
  name: 'AES',
  type: 'block',
  blockSize: BLOCK_SIZE,
  keySizes: [16, 24, 32],
  create(key) {
    return createAesCipher(key);
  },
};

export function createAesCipher(key: Uint8Array): BlockCipher {
  if (key.length !== 16 && key.length !== 24 && key.length !== 32) {
    throw new Error('AES key must be 128, 192, or 256 bits.');
  }

  const encryptionKey = nobleAesUnsafe.expandKeyLE(key);
  const decryptionKey = nobleAesUnsafe.expandKeyDecLE(key);

  return {
    blockSize: BLOCK_SIZE,

    encryptBlock(input, inputOffset, output, outputOffset) {
      transformBlock(encryptionKey, input, inputOffset, output, outputOffset, nobleAesUnsafe.encrypt);
    },

    decryptBlock(input, inputOffset, output, outputOffset) {
      transformBlock(decryptionKey, input, inputOffset, output, outputOffset, nobleAesUnsafe.decrypt);
    },

    encrypt(input, output) {
      assertBlocks(input, output);
      return transformBlocks(encryptionKey, input, output, nobleAesUnsafe.encrypt);
    },

    decrypt(input, output) {
      assertBlocks(input, output);
      return transformBlocks(decryptionKey, input, output, nobleAesUnsafe.decrypt);
    },
  };
}

type NobleAesTransform = typeof nobleAesUnsafe.encrypt;

function transformBlocks(
  expandedKey: Uint32Array,
  input: Uint8Array,
  output: Uint8Array,
  transform: NobleAesTransform,
): Uint8Array {
  for (let offset = 0; offset < input.length; offset += BLOCK_SIZE) {
    const { s0, s1, s2, s3 } = transform(
      expandedKey,
      readUint32LE(input, offset),
      readUint32LE(input, offset + 4),
      readUint32LE(input, offset + 8),
      readUint32LE(input, offset + 12),
    );
    writeUint32LE(output, offset, s0);
    writeUint32LE(output, offset + 4, s1);
    writeUint32LE(output, offset + 8, s2);
    writeUint32LE(output, offset + 12, s3);
  }

  return output;
}

function transformBlock(
  expandedKey: Uint32Array,
  input: Uint8Array,
  inputOffset: number,
  output: Uint8Array,
  outputOffset: number,
  transform: NobleAesTransform,
): void {
  const { s0, s1, s2, s3 } = transform(
    expandedKey,
    readUint32LE(input, inputOffset),
    readUint32LE(input, inputOffset + 4),
    readUint32LE(input, inputOffset + 8),
    readUint32LE(input, inputOffset + 12),
  );
  writeUint32LE(output, outputOffset, s0);
  writeUint32LE(output, outputOffset + 4, s1);
  writeUint32LE(output, outputOffset + 8, s2);
  writeUint32LE(output, outputOffset + 12, s3);
}

function readUint32LE(input: Uint8Array, offset: number): number {
  return (
    input[offset]
    | (input[offset + 1] << 8)
    | (input[offset + 2] << 16)
    | (input[offset + 3] << 24)
  ) >>> 0;
}

function writeUint32LE(output: Uint8Array, offset: number, value: number): void {
  output[offset] = value;
  output[offset + 1] = value >>> 8;
  output[offset + 2] = value >>> 16;
  output[offset + 3] = value >>> 24;
}

function assertBlocks(input: Uint8Array, output: Uint8Array): void {
  if (input.length % BLOCK_SIZE !== 0) {
    throw new Error('AES input length must be a multiple of 128 bits.');
  }
  if (output.length !== input.length) {
    throw new Error('AES output length must equal input length.');
  }
}
