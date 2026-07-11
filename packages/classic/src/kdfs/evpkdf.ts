import { bytesToWordArray, CryptoJS, wordArrayToBytes } from '../adapter/crypto-js.js';
import type { KdfComponent } from '@crypto/core';

export interface EvpKdfParams {
  passphrase: Uint8Array | string;
  salt: Uint8Array | string;
  iterations?: number;
  length: number;
  hash?: string;
}

export const evpKdf: KdfComponent<'EvpKDF'> = {
  kind: 'kdf',
  name: 'EvpKDF',
  derive(params) {
    return deriveEvpKdf(params as EvpKdfParams);
  },
};

export function deriveEvpKdf(params: EvpKdfParams): Uint8Array {
  assertPositiveInteger(params.length, 'EvpKDF length');
  if (params.iterations !== undefined) {
    assertPositiveInteger(params.iterations, 'EvpKDF iterations');
  }

  const options: EvpKdfCryptoJsOptions = {
    keySize: params.length / 4,
    iterations: params.iterations ?? 1,
  };
  const hasher = getHasher(params.hash);
  if (hasher) {
    options.hasher = hasher;
  }

  const derived = CryptoJS.EvpKDF(toCryptoJsInput(params.passphrase), toCryptoJsInput(params.salt), options);
  return wordArrayToBytes(derived);
}

interface EvpKdfCryptoJsOptions {
  keySize: number;
  iterations: number;
  hasher?: typeof CryptoJS.algo.MD5;
}

function toCryptoJsInput(input: Uint8Array | string): CryptoJS.lib.WordArray | string {
  return typeof input === 'string' ? input : bytesToWordArray(input);
}

function getHasher(hash: string | undefined): typeof CryptoJS.algo.MD5 | undefined {
  if (!hash) {
    return undefined;
  }

  const hasher = (CryptoJS.algo as Record<string, unknown>)[normalizeHashName(hash)];
  if (!hasher) {
    throw new Error(`Unsupported EvpKDF hash: ${hash}`);
  }
  return hasher as typeof CryptoJS.algo.MD5;
}

function normalizeHashName(hash: string): string {
  return hash.replaceAll('-', '').toUpperCase();
}

function assertPositiveInteger(value: number, label: string): void {
  if (!Number.isInteger(value) || value <= 0) {
    throw new RangeError(`${label} must be a positive integer.`);
  }
}
