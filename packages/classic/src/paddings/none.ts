import { assertBlockMultiple, type PaddingComponent } from '@jscrypto/core';

export const noPadding: PaddingComponent<'NoPadding'> = {
  kind: 'padding',
  name: 'NoPadding',

  pad(input, blockSize) {
    assertMultiple(input, blockSize);
    return input.slice();
  },

  unpad(input, blockSize) {
    assertMultiple(input, blockSize);
    return input.slice();
  },
};

function assertMultiple(input: Uint8Array, blockSize: number): void {
  assertBlockMultiple(input, blockSize, 'NoPadding');
}
