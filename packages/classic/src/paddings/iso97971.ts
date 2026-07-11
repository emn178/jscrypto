import {
  assertBlockSize as assertCoreBlockSize,
  assertPaddedInput as assertCorePaddedInput,
  type PaddingComponent,
} from '@crypto/core';

export const iso97971: PaddingComponent<'Iso97971'> = {
  kind: 'padding',
  name: 'Iso97971',

  pad(input, blockSize) {
    assertBlockSize(blockSize);
    const paddingLength = getPaddingLength(input.length, blockSize);
    const output = new Uint8Array(input.length + paddingLength);
    output.set(input);
    output[input.length] = 0x80;
    return output;
  },

  unpad(input, blockSize) {
    assertPaddedInput(input, blockSize);

    let index = input.length - 1;
    while (index >= 0 && input[index] === 0) {
      index--;
    }

    if (index < 0 || input[index] !== 0x80) {
      throw new Error('Invalid ISO/IEC 9797-1 padding.');
    }

    return input.slice(0, index);
  },
};

function assertBlockSize(blockSize: number): void {
  assertCoreBlockSize(blockSize);
}

function assertPaddedInput(input: Uint8Array, blockSize: number): void {
  assertCorePaddedInput(input, blockSize, 'ISO/IEC 9797-1');
}

function getPaddingLength(inputLength: number, blockSize: number): number {
  const remainder = (inputLength + 1) % blockSize;
  return 1 + (remainder === 0 ? 0 : blockSize - remainder);
}
