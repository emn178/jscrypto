import type { PresetComponent } from '@jscrypto/core';
import { createHash } from './component.js';
import { sha1 as sha1Digest } from 'js-sha1';

export const sha1 = createHash('SHA1', 64, 20, (input) => new Uint8Array(sha1Digest.arrayBuffer(input)));

export const sha1Preset: PresetComponent<'sha1'> = {
  kind: 'preset',
  name: 'sha1',
  components() {
    return [sha1];
  },
};
