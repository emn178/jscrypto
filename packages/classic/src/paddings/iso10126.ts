import {
  assertBlockSize as assertCoreBlockSize,
  assertPaddedInput as assertCorePaddedInput,
  getBlockPaddingLength,
  type PaddingComponent,
} from '@jscrypto/core';

export const iso10126: PaddingComponent<'Iso10126'> = {
  kind: 'padding',
  name: 'Iso10126',

  pad(input, blockSize) {
    assertBlockSize(blockSize);
    const paddingLength = getPaddingLength(input.length, blockSize);
    const output = new Uint8Array(input.length + paddingLength);
    output.set(input);
    fillRandom(output.subarray(input.length, output.length - 1));
    output[output.length - 1] = paddingLength;
    return output;
  },

  unpad(input, blockSize) {
    assertPaddedInput(input, blockSize);
    const paddingLength = input[input.length - 1];
    if (paddingLength === 0 || paddingLength > blockSize || paddingLength > input.length) {
      throw new Error('Invalid ISO 10126 padding.');
    }
    return input.slice(0, input.length - paddingLength);
  },
};

function assertBlockSize(blockSize: number): void {
  assertCoreBlockSize(blockSize, { max: 255 });
}

function assertPaddedInput(input: Uint8Array, blockSize: number): void {
  assertCorePaddedInput(input, blockSize, 'ISO 10126', { max: 255 });
}

function getPaddingLength(inputLength: number, blockSize: number): number {
  return getBlockPaddingLength(inputLength, blockSize);
}

function fillRandom(bytes: Uint8Array): void {
  if (bytes.length === 0) {
    return;
  }

  const crypto = globalThis as typeof globalThis & {
    crypto?: {
      getRandomValues<T extends Uint8Array>(array: T): T;
    };
  };
  crypto.crypto?.getRandomValues(bytes);
  if (bytes.some((byte) => byte !== 0)) {
    return;
  }

  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Math.floor(Math.random() * 256);
  }
}
