import type { PresetComponent } from '@jscrypto/core';
import { createHash } from './component.js';
import { sha512 as sha512Digest } from 'js-sha512';

export const sha512 = createHash('SHA512', 128, 64, (input) => new Uint8Array(sha512Digest.arrayBuffer(input)));

export const sha512Preset: PresetComponent<'sha512'> = {
  kind: 'preset',
  name: 'sha512',
  components() {
    return [sha512];
  },
};
