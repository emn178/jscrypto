import type { BlockCipher, CipherComponent, PresetComponent } from '@jscrypto/core';
import {
  speck128_128 as speck128_128Impl,
  speck128_192 as speck128_192Impl,
  speck128_256 as speck128_256Impl,
  speck32_64 as speck32_64Impl,
  speck48_72 as speck48_72Impl,
  speck48_96 as speck48_96Impl,
  speck64_96 as speck64_96Impl,
  speck64_128 as speck64_128Impl,
  speck96_96 as speck96_96Impl,
  speck96_144 as speck96_144Impl,
} from 'js-speck';

export type SpeckVariantName =
  | '32-64'
  | '48-72'
  | '48-96'
  | '64-96'
  | '64-128'
  | '96-96'
  | '96-144'
  | '128-128'
  | '128-192'
  | '128-256';

type SpeckImpl = {
  readonly blockBytes: number;
  readonly keyBytes: number;
  encrypt(key: Uint8Array, data: Uint8Array): ArrayLike<number>;
  decrypt(key: Uint8Array, data: Uint8Array): ArrayLike<number>;
};

const variants: Record<SpeckVariantName, SpeckImpl> = {
  '32-64': speck32_64Impl,
  '48-72': speck48_72Impl,
  '48-96': speck48_96Impl,
  '64-96': speck64_96Impl,
  '64-128': speck64_128Impl,
  '96-96': speck96_96Impl,
  '96-144': speck96_144Impl,
  '128-128': speck128_128Impl,
  '128-192': speck128_192Impl,
  '128-256': speck128_256Impl,
};

export function createSpeckCipher(variant: SpeckVariantName, key: Uint8Array): BlockCipher {
  if (!variant) {
    throw new Error('SPECK variant is required.');
  }

  const impl = variants[variant];
  if (!impl) {
    throw new Error(`Unknown SPECK variant: ${String(variant)}.`);
  }

  if (key.length !== impl.keyBytes) {
    throw new Error(`SPECK ${variant} key must be ${impl.keyBytes * 8} bits.`);
  }

  const blockSize = impl.blockBytes;

  return {
    blockSize,

    encryptBlock(input, inputOffset, output, outputOffset) {
      transformBlock(impl, key, input, inputOffset, output, outputOffset, true);
    },

    decryptBlock(input, inputOffset, output, outputOffset) {
      transformBlock(impl, key, input, inputOffset, output, outputOffset, false);
    },

    encrypt(input, output) {
      return transformBlocks(impl, key, input, output, true);
    },

    decrypt(input, output) {
      return transformBlocks(impl, key, input, output, false);
    },
  };
}

function createComponent<Name extends string>(
  name: Name,
  variant: SpeckVariantName,
): CipherComponent<Name> {
  const impl = variants[variant];
  return {
    kind: 'cipher',
    name,
    type: 'block',
    blockSize: impl.blockBytes,
    keySizes: [impl.keyBytes],
    create(key) {
      return createSpeckCipher(variant, key);
    },
  };
}

export const speck32_64 = createComponent('SPECK32/64', '32-64');
export const speck48_72 = createComponent('SPECK48/72', '48-72');
export const speck48_96 = createComponent('SPECK48/96', '48-96');
export const speck64_96 = createComponent('SPECK64/96', '64-96');
export const speck64_128 = createComponent('SPECK64/128', '64-128');
export const speck96_96 = createComponent('SPECK96/96', '96-96');
export const speck96_144 = createComponent('SPECK96/144', '96-144');
export const speck128_128 = createComponent('SPECK128/128', '128-128');
export const speck128_192 = createComponent('SPECK128/192', '128-192');
export const speck128_256 = createComponent('SPECK128/256', '128-256');

export const allSpeckComponents: readonly CipherComponent[] = [
  speck32_64,
  speck48_72,
  speck48_96,
  speck64_96,
  speck64_128,
  speck96_96,
  speck96_144,
  speck128_128,
  speck128_192,
  speck128_256,
];

export const speckPreset: PresetComponent<'speck'> = {
  kind: 'preset',
  name: 'speck',
  components() {
    return allSpeckComponents;
  },
};

function transformBlocks(
  impl: SpeckImpl,
  key: Uint8Array,
  input: Uint8Array,
  output: Uint8Array,
  encrypting: boolean,
): Uint8Array {
  assertBlocks(input, output, impl.blockBytes);
  for (let offset = 0; offset < input.length; offset += impl.blockBytes) {
    transformBlock(impl, key, input, offset, output, offset, encrypting);
  }
  return output;
}

function transformBlock(
  impl: SpeckImpl,
  key: Uint8Array,
  input: Uint8Array,
  inputOffset: number,
  output: Uint8Array,
  outputOffset: number,
  encrypting: boolean,
): void {
  const block = input.subarray(inputOffset, inputOffset + impl.blockBytes);
  if (block.length !== impl.blockBytes) {
    throw new Error(`SPECK block must be ${impl.blockBytes * 8} bits.`);
  }
  const transformed = encrypting ? impl.encrypt(key, block) : impl.decrypt(key, block);
  output.set(transformed, outputOffset);
}

function assertBlocks(input: Uint8Array, output: Uint8Array, blockSize: number): void {
  if (input.length % blockSize !== 0) {
    throw new Error(`SPECK input length must be a multiple of ${blockSize * 8} bits.`);
  }
  if (output.length !== input.length) {
    throw new Error('SPECK output length must equal input length.');
  }
}
