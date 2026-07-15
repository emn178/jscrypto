import type { Registry } from '@jscrypto/core';
import { md5 } from './md5.js';
import { ripemd160 } from './ripemd160.js';
import { sha1 } from './sha1.js';
import { sha224 } from './sha224.js';
import { sha256 } from './sha256.js';
import { keccak512, sha3 } from './sha3.js';
import { sha384 } from './sha384.js';
import { sha512 } from './sha512.js';

export function registerClassicHashes(registry: Registry): Registry {
  for (const hash of [md5, sha1, sha224, sha256, sha384, sha512, keccak512, sha3, ripemd160]) {
    if (!registry.has('hash', hash.name)) {
      registry.useHash(hash);
    }
  }
  return registry;
}
