import { createRegistry, type PresetComponent, type Registry } from '@jscrypto/core';
import { aes } from '@jscrypto/ciphers';
import { opensslFormat } from '@jscrypto/formats';
import { hashesPreset } from '@jscrypto/hashes';
import { hkdfPreset, pbkdf2 } from '@jscrypto/kdfs';
import { cbc, cfb, ctr, ecb, gcm, ofb } from '@jscrypto/modes';
import { noPadding, pkcs5, pkcs7 } from '@jscrypto/paddings';

export function basicPreset(): PresetComponent<'basic'> {
  return {
    kind: 'preset',
    name: 'basic',
    components() {
      return [
        aes,
        cbc,
        cfb,
        ctr,
        ecb,
        gcm,
        ofb,
        pkcs5,
        noPadding,
        pkcs7,
        pbkdf2,
        hkdfPreset,
        opensslFormat,
        hashesPreset,
      ];
    },
  };
}

export function createBasicRegistry(): Registry {
  return createRegistry().use(basicPreset());
}

export const registry: Registry = createBasicRegistry();
