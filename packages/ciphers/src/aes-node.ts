import type { BlockCipher, CipherComponent, PresetComponent } from '@jscrypto/core';
import { createCipheriv, createDecipheriv } from 'node:crypto';
import { createAesGcmComponent } from './aes-gcm.js';

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

export const aesGcm = createAesGcmComponent();

export const aesPreset: PresetComponent<'aes'> = {
  kind: 'preset',
  name: 'aes',
  components() {
    return [aes, aesGcm];
  },
};

export function createAesCipher(key: Uint8Array): BlockCipher {
  if (key.length !== 16 && key.length !== 24 && key.length !== 32) {
    throw new Error('AES key must be 128, 192, or 256 bits.');
  }

  const algorithm = `aes-${key.length * 8}-ecb`;
  return {
    blockSize: BLOCK_SIZE,

    encrypt(input, output) {
      assertBlocks(input, output);
      return cryptBlocks(algorithm, key, input, output, true);
    },

    decrypt(input, output) {
      assertBlocks(input, output);
      return cryptBlocks(algorithm, key, input, output, false);
    },
  };
}

function assertBlocks(input: Uint8Array, output: Uint8Array): void {
  if (input.length % BLOCK_SIZE !== 0) {
    throw new Error('AES input length must be a multiple of 128 bits.');
  }
  if (output.length !== input.length) {
    throw new Error('AES output length must equal input length.');
  }
}

function cryptBlocks(
  algorithm: string,
  key: Uint8Array,
  input: Uint8Array,
  output: Uint8Array,
  encrypt: boolean,
): Uint8Array {
  const cipher = encrypt
    ? createCipheriv(algorithm, key, null)
    : createDecipheriv(algorithm, key, null);
  cipher.setAutoPadding(false);
  const result = cipher.update(input);
  const final = cipher.final();
  output.set(result, 0);
  output.set(final, result.length);
  return output;
}
