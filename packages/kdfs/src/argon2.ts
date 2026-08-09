import {
  argon2d as nobleArgon2d,
  argon2i as nobleArgon2i,
  argon2id as nobleArgon2id,
} from '@noble/hashes/argon2.js';
import type { KdfComponent, PresetComponent } from '@jscrypto/core';

declare const TextEncoder: {
  new(): { encode(input: string): Uint8Array };
};

export type Argon2Mode = 'id' | 'i' | 'd';

export interface Argon2Params {
  input: Uint8Array | string;
  salt: Uint8Array | string;
  length: number;
  mode?: Argon2Mode;
  t: number;
  m: number;
  p: number;
  maxmem?: number;
}

type Argon2Impl = (input: Uint8Array, salt: Uint8Array, options: {
  t: number;
  m: number;
  p: number;
  dkLen: number;
  maxmem?: number;
}) => Uint8Array;

const ARGON2_IMPL: Record<Argon2Mode, Argon2Impl> = {
  id: nobleArgon2id,
  i: nobleArgon2i,
  d: nobleArgon2d,
};

export const argon2: KdfComponent<'Argon2'> = {
  kind: 'kdf',
  name: 'Argon2',
  derive(params) {
    return deriveArgon2(params as Argon2Params);
  },
};

export const argon2Preset: PresetComponent<'argon2'> = {
  kind: 'preset',
  name: 'argon2',
  components() {
    return [argon2];
  },
};

export function deriveArgon2(params: Argon2Params): Uint8Array {
  if (params === undefined || params === null || typeof params !== 'object') {
    throw new TypeError('Argon2 requires params.');
  }
  if (params.input === undefined || params.input === null) {
    throw new TypeError('Argon2 requires input.');
  }
  if (params.salt === undefined || params.salt === null) {
    throw new TypeError('Argon2 requires salt.');
  }

  const mode = params.mode ?? 'id';
  const impl = ARGON2_IMPL[mode];
  if (!impl) {
    throw new RangeError("Argon2 mode must be 'id', 'i', or 'd'.");
  }

  assertPositiveInteger(params.length, 'Argon2 length');
  assertPositiveInteger(params.t, 'Argon2 t');
  assertPositiveInteger(params.m, 'Argon2 m');
  assertPositiveInteger(params.p, 'Argon2 p');

  const options: {
    t: number;
    m: number;
    p: number;
    dkLen: number;
    maxmem?: number;
  } = {
    t: params.t,
    m: params.m,
    p: params.p,
    dkLen: params.length,
  };
  if (params.maxmem !== undefined) {
    assertPositiveInteger(params.maxmem, 'Argon2 maxmem');
    options.maxmem = params.maxmem;
  }

  return impl(toBytes(params.input), toBytes(params.salt), options);
}

function toBytes(input: Uint8Array | string): Uint8Array {
  return typeof input === 'string' ? new TextEncoder().encode(input) : input;
}

function assertPositiveInteger(value: number, label: string): void {
  if (!Number.isInteger(value) || value <= 0) {
    throw new RangeError(`${label} must be a positive integer.`);
  }
}
