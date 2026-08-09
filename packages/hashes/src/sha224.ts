import type { PresetComponent } from '@jscrypto/core';
import { createHash } from './component.js';
import { sha224 as sha224Digest } from 'js-sha256';

export const sha224 = createHash('SHA224', 64, 28, (input) => new Uint8Array(sha224Digest.arrayBuffer(input)));

export const sha224Preset: PresetComponent<'sha224'> = {
  kind: 'preset',
  name: 'sha224',
  components() {
    return [sha224];
  },
};
