import { concatBytes } from '@jscrypto/core';
import type { HashComponent, KdfComponent } from '@jscrypto/core';
import { hmac } from './hmac.js';

declare const TextEncoder: {
  new(): { encode(input: string): Uint8Array };
};

export interface Pbkdf2Params {
  input: Uint8Array | string;
  salt: Uint8Array | string;
  iterations: number;
  length: number;
  hash?: string;
}

export interface DerivePbkdf2Params extends Omit<Pbkdf2Params, 'hash'> {
  hash: HashComponent;
}

export const pbkdf2: KdfComponent<'PBKDF2'> = {
  kind: 'kdf',
  name: 'PBKDF2',
  derive(params, context) {
    const options = params as Pbkdf2Params;
    return derivePbkdf2({
      ...options,
      hash: context.getHash(options.hash ?? 'SHA256'),
    });
  },
};

export function derivePbkdf2(params: DerivePbkdf2Params): Uint8Array {
  assertPositiveInteger(params.iterations, 'PBKDF2 iterations');
  assertPositiveInteger(params.length, 'PBKDF2 length');
  if (params.input === undefined || params.input === null) {
    throw new TypeError('PBKDF2 requires input.');
  }

  const password = toBytes(params.input);
  const salt = toBytes(params.salt);
  const blocks: Uint8Array[] = [];
  const blockCount = Math.ceil(params.length / params.hash.digestSize);

  for (let index = 1; index <= blockCount; index++) {
    const counter = new Uint8Array([
      (index >>> 24) & 0xff,
      (index >>> 16) & 0xff,
      (index >>> 8) & 0xff,
      index & 0xff,
    ]);
    let block = hmac(params.hash, password, concatBytes(salt, counter));
    const result = block.slice();
    for (let iteration = 1; iteration < params.iterations; iteration++) {
      block = hmac(params.hash, password, block);
      for (let i = 0; i < result.length; i++) {
        result[i] ^= block[i];
      }
    }
    blocks.push(result);
  }

  return concatBytes(...blocks).slice(0, params.length);
}

function toBytes(input: Uint8Array | string): Uint8Array {
  return typeof input === 'string' ? new TextEncoder().encode(input) : input;
}

function assertPositiveInteger(value: number, label: string): void {
  if (!Number.isInteger(value) || value <= 0) {
    throw new RangeError(`${label} must be a positive integer.`);
  }
}
