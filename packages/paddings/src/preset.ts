import type { PresetComponent } from '@jscrypto/core';
import { ansiX923Preset } from './ansi-x923.js';
import { iso10126Preset } from './iso10126.js';
import { iso97971Preset } from './iso97971.js';
import { noPaddingPreset } from './none.js';
import { pkcs5Preset } from './pkcs5.js';
import { pkcs7Preset } from './pkcs7.js';
import { zeroPaddingPreset } from './zero.js';

export function paddingsPreset(): PresetComponent<'paddings'> {
  return {
    kind: 'preset',
    name: 'paddings',
    components() {
      return [pkcs7Preset, pkcs5Preset, noPaddingPreset, ansiX923Preset, iso10126Preset, iso97971Preset, zeroPaddingPreset];
    },
  };
}
