import {
  assertBlockMultiple as assertCoreBlockMultiple,
  assertIv,
  xorBytes,
  type BlockCipher,
  type ModeComponent,
  type Transform,
} from '@crypto/core';

export const cbc: ModeComponent<'CBC'> = {
  kind: 'mode',
  name: 'CBC',
  requiresPadding: true,
  createEncryptor({ cipher, iv }) {
    assertIv(cipher.blockSize, iv, 'CBC');
    return createCbcEncryptor(cipher, iv);
  },
  createDecryptor({ cipher, iv }) {
    assertIv(cipher.blockSize, iv, 'CBC');
    return createCbcDecryptor(cipher, iv);
  },
};

function createCbcEncryptor(cipher: BlockCipher, iv: Uint8Array): Transform {
  let previous = iv;

  return {
    process(input) {
      assertBlockMultiple(cipher.blockSize, input);
      const output = new Uint8Array(input.length);

      for (let offset = 0; offset < input.length; offset += cipher.blockSize) {
        const block = xorBytes(input.subarray(offset, offset + cipher.blockSize), previous);
        const encrypted = cipher.encryptBlock(block);
        output.set(encrypted, offset);
        previous = encrypted;
      }

      return output;
    },

    finalize(input = new Uint8Array()) {
      return input.length === 0 ? new Uint8Array() : this.process(input);
    },
  };
}

function createCbcDecryptor(cipher: BlockCipher, iv: Uint8Array): Transform {
  let previous = iv;

  return {
    process(input) {
      assertBlockMultiple(cipher.blockSize, input);
      const output = new Uint8Array(input.length);

      for (let offset = 0; offset < input.length; offset += cipher.blockSize) {
        const block = input.subarray(offset, offset + cipher.blockSize);
        const decrypted = cipher.decryptBlock(block);
        output.set(xorBytes(decrypted, previous), offset);
        previous = block.slice();
      }

      return output;
    },

    finalize(input = new Uint8Array()) {
      return input.length === 0 ? new Uint8Array() : this.process(input);
    },
  };
}

function assertBlockMultiple(blockSize: number, input: Uint8Array): void {
  assertCoreBlockMultiple(input, blockSize, 'CBC');
}
