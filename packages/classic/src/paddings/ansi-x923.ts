import {
  assertBlockSize as assertCoreBlockSize,
  assertPaddedInput as assertCorePaddedInput,
  getBlockPaddingLength,
  type PaddingComponent,
} from '@crypto/core';

export const ansiX923: PaddingComponent<'AnsiX923'> = {
  kind: 'padding',
  name: 'AnsiX923',

  pad(input, blockSize) {
    assertBlockSize(blockSize);
    const paddingLength = getPaddingLength(input.length, blockSize);
    const output = new Uint8Array(input.length + paddingLength);
    output.set(input);
    output[output.length - 1] = paddingLength;
    return output;
  },

  unpad(input, blockSize) {
    assertPaddedInput(input, blockSize);
    const paddingLength = input[input.length - 1];
    if (paddingLength === 0 || paddingLength > blockSize || paddingLength > input.length) {
      throw new Error('Invalid ANSI X9.23 padding.');
    }

    for (let i = input.length - paddingLength; i < input.length - 1; i++) {
      if (input[i] !== 0) {
        throw new Error('Invalid ANSI X9.23 padding.');
      }
    }

    return input.slice(0, input.length - paddingLength);
  },
};

function assertBlockSize(blockSize: number): void {
  assertCoreBlockSize(blockSize, { max: 255 });
}

function assertPaddedInput(input: Uint8Array, blockSize: number): void {
  assertCorePaddedInput(input, blockSize, 'ANSI X9.23', { max: 255 });
}

function getPaddingLength(inputLength: number, blockSize: number): number {
  return getBlockPaddingLength(inputLength, blockSize);
}
