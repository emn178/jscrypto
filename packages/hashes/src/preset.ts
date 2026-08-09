import type { PresetComponent } from '@jscrypto/core';
import { md5Preset } from './md5.js';
import { ripemd160Preset } from './ripemd160.js';
import { sha1Preset } from './sha1.js';
import { sha224Preset } from './sha224.js';
import { sha256Preset } from './sha256.js';
import { keccak512Preset } from './sha3.js';
import { sha384Preset } from './sha384.js';
import { sha512Preset } from './sha512.js';

export const hashesPreset: PresetComponent<'hashes'> = {
  kind: 'preset',
  name: 'hashes',
  components() {
    return [
      md5Preset,
      sha1Preset,
      sha224Preset,
      sha256Preset,
      sha384Preset,
      sha512Preset,
      keccak512Preset,
      ripemd160Preset,
    ];
  },
};

export const classicHashesPreset: PresetComponent<'classic-hashes'> = {
  kind: 'preset',
  name: 'classic-hashes',
  components: hashesPreset.components,
};
