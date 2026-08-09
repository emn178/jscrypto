import { createRegistry } from '@jscrypto/core';
import { classicCiphersPreset } from '@jscrypto/ciphers';
import { formatsPreset } from '@jscrypto/formats';
import { classicKdfsPreset } from '@jscrypto/kdfs';
import { modesPreset } from '@jscrypto/modes';
import { paddingsPreset } from '@jscrypto/paddings';

export function classicPreset() {
  return {
    kind: 'preset',
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
