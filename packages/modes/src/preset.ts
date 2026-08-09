import type { PresetComponent } from '@jscrypto/core';
import { cbcPreset } from './cbc.js';
import { cfbPreset } from './cfb.js';
import { ctrPreset } from './ctr.js';
import { ecbPreset } from './ecb.js';
import { gcmPreset } from './gcm.js';
import { ofbPreset } from './ofb.js';

export function modesPreset(): PresetComponent<'modes'> {
  return {
    kind: 'preset',
    name: 'modes',
    components() {
      return [cbcPreset, cfbPreset, ctrPreset, ecbPreset, gcmPreset, ofbPreset];
    },
  };
}
