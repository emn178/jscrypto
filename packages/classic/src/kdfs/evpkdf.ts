import { concatBytes } from '@jscrypto/core';
import type { HashComponent, KdfComponent } from '@jscrypto/core';

declare const TextEncoder: {
  new(): { encode(input: string): Uint8Array };
};

export interface EvpKdfParams {
  passphrase: Uint8Array | string;
  salt: Uint8Array | string;
  iterations?: number;
  length: number;
  hash?: string;
}

export interface DeriveEvpKdfParams extends Omit<EvpKdfParams, 'hash'> {
  hash: HashComponent;
}

export const evpKdf: KdfComponent<'EvpKDF'> = {
  kind: 'kdf',
  name: 'EvpKDF',
  derive(params, context) {
    const options = params as EvpKdfParams;
    return deriveEvpKdf({
      ...options,
      hash: context.getHash(options.hash ?? 'MD5'),
    });
  },
};

export function deriveEvpKdf(params: DeriveEvpKdfParams): Uint8Array {
  assertPositiveInteger(params.length, 'EvpKDF length');
  if (params.iterations !== undefined) {
    assertPositiveInteger(params.iterations, 'EvpKDF iterations');
  }

  const password = toBytes(params.passphrase);
  const salt = toBytes(params.salt);
  const blocks: Uint8Array[] = [];
  let previous = new Uint8Array(0);
  let length = 0;

  while (length < params.length) {
    let block = params.hash.hash(concatBytes(previous, password, salt));
    for (let i = 1; i < (params.iterations ?? 1); i++) {
      block = params.hash.hash(block);
    }
    blocks.push(block);
    previous = block;
    length += block.length;
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
