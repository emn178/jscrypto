import { createRegistry, type PresetComponent, type Registry } from '@jscrypto/core';
import { ciphersPreset } from '@jscrypto/ciphers';
import { formatsPreset } from '@jscrypto/formats';
import { hashesPreset } from '@jscrypto/hashes';
import { kdfsPreset } from '@jscrypto/kdfs';
import { modesPreset } from '@jscrypto/modes';
import { paddingsPreset } from '@jscrypto/paddings';

export function allPreset(): PresetComponent<'all'> {
  return {
    kind: 'preset',
    name: 'all',
    components() {
      return [
        ciphersPreset(),
        modesPreset(),
        paddingsPreset(),
        kdfsPreset(),
        formatsPreset(),
        hashesPreset,
      ];
    },
  };
}

export function createAllRegistry(): Registry {
  return createRegistry().use(allPreset());
}

export const allRegistry: Registry = createAllRegistry();
