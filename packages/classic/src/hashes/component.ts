import type { HashComponent } from '@jscrypto/core';

export function createHash<Name extends string>(
  name: Name,
  blockSize: number,
  digestSize: number,
  hash: (input: Uint8Array) => Uint8Array,
): HashComponent<Name> {
  return {
    kind: 'hash',
    name,
    blockSize,
    digestSize,
    hash,
  };
}
