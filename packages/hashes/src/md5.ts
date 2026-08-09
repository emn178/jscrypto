import type { PresetComponent } from '@jscrypto/core';
import { createHash } from './component.js';
import { md5 as md5Digest } from 'js-md5';

export const md5 = createHash('MD5', 64, 16, (input) => new Uint8Array(md5Digest.arrayBuffer(input)));

export const md5Preset: PresetComponent<'md5'> = {
  kind: 'preset',
  name: 'md5',
  components() {
    return [md5];
  },
};
