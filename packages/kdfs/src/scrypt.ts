import { scrypt as nobleScrypt } from '@noble/hashes/scrypt.js';
import type { KdfComponent, PresetComponent } from '@jscrypto/core';

declare const TextEncoder: {
  new(): { encode(input: string): Uint8Array };
};

export interface ScryptParams {
  input: Uint8Array | string;
  salt: Uint8Array | string;
  length: number;
  N: number;
  r: number;
  p: number;
  maxmem?: number;
}

export const scrypt: KdfComponent<'Scrypt'> = {
  kind: 'kdf',
  name: 'Scrypt',
  derive(params) {
    return deriveScrypt(params as ScryptParams);
  },
};

export const scryptPreset: PresetComponent<'scrypt'> = {
  kind: 'preset',
  name: 'scrypt',
  components() {
    return [scrypt];
  },
};

export function deriveScrypt(params: ScryptParams): Uint8Array {
  if (params === undefined || params === null || typeof params !== 'object') {
    throw new TypeError('Scrypt requires params.');
  }
  if (params.input === undefined || params.input === null) {
    throw new TypeError('Scrypt requires input.');
  }
  if (params.salt === undefined || params.salt === null) {
    throw new TypeError('Scrypt requires salt.');
  }

  assertPositiveInteger(params.length, 'Scrypt length');
  assertPositiveInteger(params.N, 'Scrypt N');
  assertPositiveInteger(params.r, 'Scrypt r');
  assertPositiveInteger(params.p, 'Scrypt p');
  if ((params.N & (params.N - 1)) !== 0) {
    throw new RangeError('Scrypt N must be a power of 2.');
  }

  const options: {
    N: number;
    r: number;
    p: number;
    dkLen: number;
    maxmem?: number;
  } = {
    N: params.N,
    r: params.r,
    p: params.p,
    dkLen: params.length,
  };
  if (params.maxmem !== undefined) {
    assertPositiveInteger(params.maxmem, 'Scrypt maxmem');
    options.maxmem = params.maxmem;
  }

  return nobleScrypt(toBytes(params.input), toBytes(params.salt), options);
}

function toBytes(input: Uint8Array | string): Uint8Array {
  return typeof input === 'string' ? new TextEncoder().encode(input) : input;
}

function assertPositiveInteger(value: number, label: string): void {
  if (!Number.isInteger(value) || value <= 0) {
    throw new RangeError(`${label} must be a positive integer.`);
  }
}
