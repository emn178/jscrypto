import {
  assertBlockMultiple as assertCoreBlockMultiple,
  assertIv,
  xorBytes,
  type BlockCipher,
  type ModeComponent,
  type Transform,
} from '@jscrypto/core';

export const cbc: ModeComponent<'CBC'> = {
  kind: 'mode',
  name: 'CBC',
  requiresPadding: true,
  getIvSize: (cipher) => cipher.blockSize,
  createEncryptor({ cipher, iv, options }) {
    assertIv(cipher.blockSize, iv, 'CBC');
    return createCbcEncryptor(cipher, iv, getInplace(options));
  },
  createDecryptor({ cipher, iv, options }) {
    assertIv(cipher.blockSize, iv, 'CBC');
    return createCbcDecryptor(cipher, iv, getInplace(options));
  },
};

function createCbcEncryptor(cipher: BlockCipher, iv: Uint8Array, inplace: boolean): Transform {
  let previous = iv;

  return {
    process(input) {
      assertBlockMultiple(cipher.blockSize, input);
      const output = inplace ? input : new Uint8Array(input.length);

      for (let offset = 0; offset < input.length; offset += cipher.blockSize) {
        const block = xorBytes(input.subarray(offset, offset + cipher.blockSize), previous);
        const encrypted = output.subarray(offset, offset + cipher.blockSize);
        cipher.encrypt(block, encrypted);
        previous = encrypted;
      }

      return output;
    },

    finalize(input = new Uint8Array(0)) {
      return input.length === 0 ? new Uint8Array(0) : this.process(input);
    },
  };
}

function createCbcDecryptor(cipher: BlockCipher, iv: Uint8Array, inplace: boolean): Transform {
  let previous = iv;

  return {
    process(input) {
      assertBlockMultiple(cipher.blockSize, input);
      const output = inplace ? input : new Uint8Array(input.length);

      for (let offset = 0; offset < input.length; offset += cipher.blockSize) {
        const block = input.subarray(offset, offset + cipher.blockSize);
        const current = block.slice();
        const decrypted = output.subarray(offset, offset + cipher.blockSize);
        cipher.decrypt(block, decrypted);
        for (let index = 0; index < cipher.blockSize; index++) {
          decrypted[index] ^= previous[index];
        }
        previous = current;
      }

      return output;
    },

    finalize(input = new Uint8Array(0)) {
      return input.length === 0 ? new Uint8Array(0) : this.process(input);
    },
  };
}

function assertBlockMultiple(blockSize: number, input: Uint8Array): void {
  assertCoreBlockMultiple(input, blockSize, 'CBC');
}

function getInplace(options: unknown): boolean {
  return typeof options === 'object' && options !== null && 'inplace' in options && options.inplace === true;
}
