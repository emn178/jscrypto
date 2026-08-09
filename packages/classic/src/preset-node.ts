import { createRegistry, type PresetComponent, type Registry } from '@jscrypto/core';
import { aesPreset } from '@jscrypto/ciphers/aes';
import { desPreset } from '@jscrypto/ciphers/des';
import { rc4Preset } from '@jscrypto/ciphers/rc4';
import { tripleDesPreset } from '@jscrypto/ciphers/triple-des';
import { formatsPreset } from '@jscrypto/formats';
import { classicKdfsPreset } from '@jscrypto/kdfs';
import { modesPreset } from '@jscrypto/modes';
import { paddingsPreset } from '@jscrypto/paddings';

function classicCiphersPreset(): PresetComponent<'classic-ciphers'> {
  return {
    kind: 'preset',
    name: 'classic-ciphers',
    components() {
      return [aesPreset, desPreset, rc4Preset, tripleDesPreset];
    },
  };
}

export function classicPreset(): PresetComponent<'classic'> {
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

export function createClassicRegistry(): Registry {
  return createRegistry().use(classicPreset());
}

export const registry: Registry = createClassicRegistry();
