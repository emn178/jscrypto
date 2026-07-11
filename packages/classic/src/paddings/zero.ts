import type { PaddingComponent } from '@crypto/core';

export const zeroPadding: PaddingComponent<'ZeroPadding'> = {
  kind: 'padding',
  name: 'ZeroPadding',

  pad(input, blockSize) {
    if (!Number.isInteger(blockSize) || blockSize <= 0) {
      throw new RangeError('blockSize must be a positive integer.');
    }

    const remainder = input.length % blockSize;
    if (remainder === 0) {
      return input.slice();
    }

    const output = new Uint8Array(input.length + blockSize - remainder);
    output.set(input);
    return output;
  },

  unpad(input) {
    let end = input.length;
    while (end > 0 && input[end - 1] === 0) {
      end--;
    }
    return input.slice(0, end);
  },
};
