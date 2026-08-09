import { assertBlockMultiple, type PaddingComponent, type PresetComponent } from '@jscrypto/core';

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

export const noPaddingPreset: PresetComponent<'none'> = {
  kind: 'preset',
  name: 'none',
  components() {
    return [noPadding];
  },
};

function assertMultiple(input: Uint8Array, blockSize: number): void {
  assertBlockMultiple(input, blockSize, 'NoPadding');
}
