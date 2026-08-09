import type { PresetComponent } from '@jscrypto/core';
import { evpKdfPreset } from './evpkdf.js';
import { hkdfPreset } from './hkdf.js';
import { pbkdf2Preset } from './pbkdf2.js';

export function classicKdfsPreset(): PresetComponent<'classic-kdfs'> {
  return {
    kind: 'preset',
    name: 'classic-kdfs',
    components() {
      return [pbkdf2Preset, evpKdfPreset];
    },
  };
}

export function kdfsPreset(): PresetComponent<'kdfs'> {
  return {
    kind: 'preset',
    name: 'kdfs',
    components() {
      return [classicKdfsPreset(), hkdfPreset];
    },
  };
}
