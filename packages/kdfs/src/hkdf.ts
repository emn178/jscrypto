import { concatBytes } from '@jscrypto/core';
import type { HashComponent, KdfComponent, PresetComponent } from '@jscrypto/core';

declare const TextEncoder: {
  new(): { encode(input: string): Uint8Array };
};

export interface HkdfParams {
  input: Uint8Array | string;
  salt?: Uint8Array | string;
  info?: Uint8Array | string;
  hash: string;
  length: number;
}

export interface HkdfExtractParams {
  input: Uint8Array | string;
  salt?: Uint8Array | string;
  hash: HashComponent;
}

export interface HkdfExpandParams {
  input: Uint8Array | string;
  info?: Uint8Array | string;
  hash: HashComponent;
  length: number;
}

export interface DeriveHkdfParams {
  input: Uint8Array | string;
  salt?: Uint8Array | string;
  info?: Uint8Array | string;
  hash: HashComponent;
  length: number;
}

export const hkdf: KdfComponent<'HKDF'> = {
  kind: 'kdf',
  name: 'HKDF',
  derive(params, context) {
    const options = params as HkdfParams;
    return deriveHkdf({
      ...options,
      hash: resolveHash(options.hash, context, 'HKDF'),
    });
  },
};

export const hkdfExtract: KdfComponent<'HKDF-Extract'> = {
  kind: 'kdf',
  name: 'HKDF-Extract',
  derive(params, context) {
    const options = params as {
      input: Uint8Array | string;
      salt?: Uint8Array | string;
      hash: string;
    };
    return extractHkdf({
      input: options.input,
      salt: options.salt,
      hash: resolveHash(options.hash, context, 'HKDF-Extract'),
    });
  },
};

export const hkdfExpand: KdfComponent<'HKDF-Expand'> = {
  kind: 'kdf',
  name: 'HKDF-Expand',
  derive(params, context) {
    const options = params as {
      input: Uint8Array | string;
      info?: Uint8Array | string;
      hash: string;
      length: number;
    };
    return expandHkdf({
      input: options.input,
      info: options.info,
      length: options.length,
      hash: resolveHash(options.hash, context, 'HKDF-Expand'),
    });
  },
};

export const hkdfPreset: PresetComponent<'hkdf'> = {
  kind: 'preset',
  name: 'hkdf',
  components() {
    return [hkdf, hkdfExtract, hkdfExpand];
  },
};

export function extractHkdf(params: HkdfExtractParams): Uint8Array {
  requireInput(params.input, 'HKDF');
  requireHash(params.hash, 'HKDF');
  if (params.salt !== undefined) {
    assertBytesOrString(params.salt, 'salt');
  }

  const hashLen = params.hash.digestSize;
  return extract(params.hash, toBytes(params.input), normalizeSalt(params.salt, hashLen));
}

export function expandHkdf(params: HkdfExpandParams): Uint8Array {
  return expandFromParams(params, 'HKDF-Expand');
}

export function deriveHkdf(params: DeriveHkdfParams): Uint8Array {
  const prk = extractHkdf(params);
  return expandFromParams({
    input: prk,
    info: params.info,
    hash: params.hash,
    length: params.length,
  }, 'HKDF');
}

function resolveHash(
  hash: string | undefined,
  context: { getHash(name: string): HashComponent },
  label: string,
): HashComponent {
  if (typeof hash !== 'string' || hash.length === 0) {
    throw new TypeError(`${label} requires hash.`);
  }
  return context.getHash(hash);
}

function expandFromParams(params: HkdfExpandParams, label: string): Uint8Array {
  requireInput(params.input, label);
  requireHash(params.hash, label);
  assertNonNegativeInteger(params.length, `${label} length`);

  const hashLen = params.hash.digestSize;
  const prk = toBytes(params.input);
  if (prk.length < hashLen) {
    throw new RangeError(`${label} input must be at least ${hashLen} bytes.`);
  }

  const maxLength = 255 * hashLen;
  if (params.length > maxLength) {
    throw new RangeError(`${label} length must be <= ${maxLength}.`);
  }

  if (params.info !== undefined) {
    assertBytesOrString(params.info, 'info');
  }

  if (params.length === 0) {
    return new Uint8Array(0);
  }

  const info = params.info === undefined ? new Uint8Array(0) : toBytes(params.info);
  return expand(params.hash, prk, info, params.length);
}

function extract(hash: HashComponent, input: Uint8Array, salt: Uint8Array): Uint8Array {
  return hmac(hash, salt, input);
}

function expand(
  hash: HashComponent,
  prk: Uint8Array,
  info: Uint8Array,
  length: number,
): Uint8Array {
  const hashLen = hash.digestSize;
  const blockCount = Math.ceil(length / hashLen);
  const blocks: Uint8Array[] = [];
  let previous: Uint8Array = new Uint8Array(0);

  for (let index = 1; index <= blockCount; index++) {
    previous = hmac(hash, prk, concatBytes(previous, info, new Uint8Array([index])));
    blocks.push(previous);
  }

  return concatBytes(...blocks).slice(0, length);
}

function hmac(hash: HashComponent, key: Uint8Array, input: Uint8Array): Uint8Array {
  const normalizedKey = key.length > hash.blockSize ? hash.hash(key) : key;
  const innerKey = new Uint8Array(hash.blockSize);
  const outerKey = new Uint8Array(hash.blockSize);
  innerKey.set(normalizedKey);
  outerKey.set(normalizedKey);

  for (let i = 0; i < hash.blockSize; i++) {
    innerKey[i] = (innerKey[i] as number) ^ 0x36;
    outerKey[i] = (outerKey[i] as number) ^ 0x5c;
  }

  return hash.hash(concatBytes(outerKey, hash.hash(concatBytes(innerKey, input))));
}

function normalizeSalt(salt: Uint8Array | string | undefined, hashLen: number): Uint8Array {
  if (salt === undefined) {
    return new Uint8Array(hashLen);
  }
  const bytes = toBytes(salt);
  return bytes.length === 0 ? new Uint8Array(hashLen) : bytes;
}

function toBytes(input: Uint8Array | string): Uint8Array {
  return typeof input === 'string' ? new TextEncoder().encode(input) : input;
}

function requireInput(value: unknown, label: string): asserts value is Uint8Array | string {
  if (value === undefined || value === null) {
    throw new TypeError(`${label} requires input.`);
  }
  assertBytesOrString(value, 'input');
}

function requireHash(value: unknown, label: string): asserts value is HashComponent {
  if (value === undefined || value === null) {
    throw new TypeError(`${label} requires hash.`);
  }
}

function assertBytesOrString(value: unknown, name: string): asserts value is Uint8Array | string {
  if (typeof value === 'string') {
    return;
  }
  if (value instanceof Uint8Array) {
    return;
  }
  throw new TypeError(`HKDF ${name} must be a Uint8Array or string.`);
}

function assertNonNegativeInteger(value: number, label: string): void {
  if (!Number.isInteger(value) || value < 0) {
    throw new RangeError(`${label} must be a non-negative integer.`);
  }
}
