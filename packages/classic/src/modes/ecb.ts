import { assertBlockMultiple as assertCoreBlockMultiple, type BlockCipher, type ModeComponent, type Transform } from '@jscrypto/core';

export const ecb: ModeComponent<'ECB'> = {
  kind: 'mode',
  name: 'ECB',
  requiresPadding: true,
  createEncryptor({ cipher }) {
    return createEcbEncryptor(cipher);
  },
  createDecryptor({ cipher }) {
    return createEcbDecryptor(cipher);
  },
};

function createEcbEncryptor(cipher: BlockCipher): Transform {
  return {
    process(input) {
      assertBlockMultiple(cipher.blockSize, input);
      const output = new Uint8Array(input.length);

      for (let offset = 0; offset < input.length; offset += cipher.blockSize) {
        output.set(cipher.encryptBlock(input.subarray(offset, offset + cipher.blockSize)), offset);
      }

      return output;
    },

    finalize(input = new Uint8Array(0)) {
      return input.length === 0 ? new Uint8Array(0) : this.process(input);
    },
  };
}

function createEcbDecryptor(cipher: BlockCipher): Transform {
  return {
    process(input) {
      assertBlockMultiple(cipher.blockSize, input);
      const output = new Uint8Array(input.length);

      for (let offset = 0; offset < input.length; offset += cipher.blockSize) {
        output.set(cipher.decryptBlock(input.subarray(offset, offset + cipher.blockSize)), offset);
      }

      return output;
    },

    finalize(input = new Uint8Array(0)) {
      return input.length === 0 ? new Uint8Array(0) : this.process(input);
    },
  };
}

function assertBlockMultiple(blockSize: number, input: Uint8Array): void {
  assertCoreBlockMultiple(input, blockSize, 'ECB');
}
