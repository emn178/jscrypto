import { createRegistry } from '@jscrypto/core';
import { aes, createAesCipher } from '@jscrypto/ciphers';
import { cbc, cfb, ctr, ecb, gcm, ofb } from '@jscrypto/modes';
import {
  ansiX923,
  iso10126,
  iso97971,
  noPadding,
  pkcs5,
  pkcs7,
  zeroPadding,
} from '@jscrypto/paddings';

export function createClassicRegistry() {
  return createRegistry()
    .use(aes)
    .use(cbc)
    .use(cfb)
    .use(ctr)
    .use(ecb)
    .use(gcm)
    .use(ofb)
    .use(pkcs7)
    .use(pkcs5)
    .use(noPadding)
    .use(ansiX923)
    .use(iso10126)
    .use(iso97971)
    .use(zeroPadding);
}

export { createAesCipher };
