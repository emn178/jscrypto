import { createRegistry } from '@jscrypto/core';
import { classicCiphersPreset } from '@jscrypto/ciphers';
import { formatsPreset } from '@jscrypto/formats';
import { modesPreset } from '@jscrypto/modes';
import { paddingsPreset } from '@jscrypto/paddings';
import { classicKdfsPreset } from '../../src/preset.js';

export function classicPreset() {
  return {
    kind: 'preset' as const,
    name: 'classic',
    components() {
      return [
        classicCiphersPreset(),
        modesPreset(),
        paddingsPreset(),
        classicKdfsPreset(),
        formatsPreset(),
      ];
    },
  };
}

export function createClassicRegistry() {
  return createRegistry().use(classicPreset());
}

export const registry = createClassicRegistry();
