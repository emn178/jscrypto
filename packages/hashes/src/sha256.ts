import type { PresetComponent } from '@jscrypto/core';
import { createHash } from './component.js';
import { sha256 as sha256Digest } from 'js-sha256';

export const sha256 = createHash('SHA256', 64, 32, (input) => new Uint8Array(sha256Digest.arrayBuffer(input)));

export const sha256Preset: PresetComponent<'sha256'> = {
  kind: 'preset',
  name: 'sha256',
  components() {
    return [sha256];
  },
};
