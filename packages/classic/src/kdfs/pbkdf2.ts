import { bytesToWordArray, CryptoJS, wordArrayToBytes } from '../adapter/crypto-js.js';
import type { KdfComponent } from '@jscrypto/core';

export interface Pbkdf2Params {
  passphrase: Uint8Array | string;
  salt: Uint8Array | string;
  iterations: number;
  length: number;
  hash?: string;
}

export const pbkdf2: KdfComponent<'PBKDF2'> = {
  kind: 'kdf',
  name: 'PBKDF2',
  derive(params) {
    return derivePbkdf2(params as Pbkdf2Params);
  },
};

export function derivePbkdf2(params: Pbkdf2Params): Uint8Array {
  assertPositiveInteger(params.iterations, 'PBKDF2 iterations');
  assertPositiveInteger(params.length, 'PBKDF2 length');

  const options: Pbkdf2CryptoJsOptions = {
    keySize: params.length / 4,
    iterations: params.iterations,
  };
  const hasher = getHasher(params.hash);
  if (hasher) {
    options.hasher = hasher;
  }

  const derived = CryptoJS.PBKDF2(toCryptoJsInput(params.passphrase), toCryptoJsInput(params.salt), options);
  return wordArrayToBytes(derived);
}

interface Pbkdf2CryptoJsOptions {
  keySize: number;
  iterations: number;
  hasher?: typeof CryptoJS.algo.SHA256;
}

function toCryptoJsInput(input: Uint8Array | string): CryptoJS.lib.WordArray | string {
  return typeof input === 'string' ? input : bytesToWordArray(input);
}

function getHasher(hash: string | undefined): typeof CryptoJS.algo.SHA256 | undefined {
  if (!hash) {
    return undefined;
  }

  const hasher = (CryptoJS.algo as Record<string, unknown>)[normalizeHashName(hash)];
  if (!hasher) {
    throw new Error(`Unsupported PBKDF2 hash: ${hash}`);
  }
  return hasher as typeof CryptoJS.algo.SHA256;
}

function normalizeHashName(hash: string): string {
  return hash.replace(/-/g, '').toUpperCase();
}

function assertPositiveInteger(value: number, label: string): void {
  if (!Number.isInteger(value) || value <= 0) {
    throw new RangeError(`${label} must be a positive integer.`);
  }
}
