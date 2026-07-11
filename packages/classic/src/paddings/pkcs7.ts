import { assertBlockSize, assertPaddedInput, getBlockPaddingLength, type PaddingComponent } from '@jscrypto/core';

export const pkcs7: PaddingComponent<'Pkcs7'> = {
  kind: 'padding',
  name: 'Pkcs7',

  pad(input, blockSize) {
    assertBlockSize(blockSize, { max: 255 });
    const paddingLength = getBlockPaddingLength(input.length, blockSize);
    const output = new Uint8Array(input.length + paddingLength);
    output.set(input);
    output.fill(paddingLength, input.length);
    return output;
  },

  unpad(input, blockSize) {
    assertPaddedInput(input, blockSize, 'PKCS#7', { max: 255 });

    const paddingLength = input[input.length - 1];
    if (paddingLength === 0 || paddingLength > blockSize || paddingLength > input.length) {
      throw new Error('Invalid PKCS#7 padding.');
    }

    for (let i = input.length - paddingLength; i < input.length; i++) {
      if (input[i] !== paddingLength) {
        throw new Error('Invalid PKCS#7 padding.');
      }
    }

    return input.slice(0, input.length - paddingLength);
  },
};
