import { concatBytes } from '@jscrypto/core';
import type { HashComponent } from '@jscrypto/core';

export function hmac(hash: HashComponent, key: Uint8Array, input: Uint8Array): Uint8Array {
  const normalizedKey = key.length > hash.blockSize ? hash.hash(key) : key;
  const innerKey = new Uint8Array(hash.blockSize);
  const outerKey = new Uint8Array(hash.blockSize);
  innerKey.set(normalizedKey);
  outerKey.set(normalizedKey);

  for (let i = 0; i < hash.blockSize; i++) {
    innerKey[i] ^= 0x36;
    outerKey[i] ^= 0x5c;
  }

  return hash.hash(concatBytes(outerKey, hash.hash(concatBytes(innerKey, input))));
}
