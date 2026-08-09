import type { PresetComponent } from '@jscrypto/core';
import { createHash } from './component.js';
import { sha384 as sha384Digest } from 'js-sha512';

export const sha384 = createHash('SHA384', 128, 48, (input) => new Uint8Array(sha384Digest.arrayBuffer(input)));

export const sha384Preset: PresetComponent<'sha384'> = {
  kind: 'preset',
  name: 'sha384',
  components() {
    return [sha384];
  },
};
