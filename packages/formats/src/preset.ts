import type { PresetComponent } from '@jscrypto/core';
import { opensslPreset } from './openssl.js';

export function formatsPreset(): PresetComponent<'formats'> {
  return {
    kind: 'preset',
    name: 'formats',
    components() {
      return [opensslPreset];
    },
  };
}
