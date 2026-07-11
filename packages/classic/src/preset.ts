import { createRegistry, type PresetComponent, type Registry } from '@jscrypto/core';
import { aes } from './ciphers/aes.js';
import { des } from './ciphers/des.js';
import { rc4, rc4Drop } from './ciphers/rc4.js';
import { tripleDes } from './ciphers/triple-des.js';
import { opensslFormat } from './formats/openssl.js';
import { evpKdf } from './kdfs/evpkdf.js';
import { pbkdf2 } from './kdfs/pbkdf2.js';
import { cbc } from './modes/cbc.js';
import { cfb } from './modes/cfb.js';
import { ctr } from './modes/ctr.js';
import { ecb } from './modes/ecb.js';
import { gcm } from './modes/gcm.js';
import { ofb } from './modes/ofb.js';
import { ansiX923 } from './paddings/ansi-x923.js';
import { iso10126 } from './paddings/iso10126.js';
import { iso97971 } from './paddings/iso97971.js';
import { noPadding } from './paddings/none.js';
import { pkcs7 } from './paddings/pkcs7.js';
import { zeroPadding } from './paddings/zero.js';

export function classicPreset(): PresetComponent<'classic'> {
  return {
    kind: 'preset',
    name: 'classic',
    components() {
      return [
        aes,
        des,
        rc4,
        rc4Drop,
        tripleDes,
        cbc,
        cfb,
        ctr,
        ecb,
        gcm,
        ofb,
        pkcs7,
        noPadding,
        ansiX923,
        iso10126,
        iso97971,
        zeroPadding,
        pbkdf2,
        evpKdf,
        opensslFormat,
      ];
    },
  };
}

export function createClassicRegistry(): Registry {
  return createRegistry().use(classicPreset());
}

export const registry: Registry = createClassicRegistry();
