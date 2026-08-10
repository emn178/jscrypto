import type { PaddingComponent, PresetComponent } from '@jscrypto/core';
import { padPkcs, unpadPkcs } from './pkcs-shared.js';

export const pkcs5: PaddingComponent<'Pkcs5'> = {
  kind: 'padding',
  name: 'Pkcs5',
  pad: padPkcs,
  unpad: unpadPkcs,
};

export const pkcs5Preset: PresetComponent<'pkcs5'> = {
  kind: 'preset',
  name: 'pkcs5',
  components() {
    return [pkcs5];
  },
};
