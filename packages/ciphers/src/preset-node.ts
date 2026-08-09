import type { PresetComponent } from '@jscrypto/core';
import { aesPreset } from './aes-node.js';
import { chacha20Preset } from './chacha20.js';
import { desPreset } from './des.js';
import { rc4Preset } from './rc4.js';
import { speckPreset } from './speck.js';
import { tripleDesPreset } from './triple-des.js';

export function classicCiphersPreset(): PresetComponent<'classic-ciphers'> {
  return {
    kind: 'preset',
    name: 'classic-ciphers',
    components() {
      return [aesPreset, desPreset, rc4Preset, tripleDesPreset];
    },
  };
}

export function ciphersPreset(): PresetComponent<'ciphers'> {
  return {
    kind: 'preset',
    name: 'ciphers',
    components() {
      return [classicCiphersPreset(), speckPreset, chacha20Preset];
    },
  };
}
