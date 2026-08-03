import { assertBlockMultiple as assertCoreBlockMultiple, type BlockCipher, type ModeComponent, type Transform } from '@jscrypto/core';

export const ecb: ModeComponent<'ECB'> = {
  kind: 'mode',
  name: 'ECB',
  requiresPadding: true,
  getIvSize: () => 0,
  createEncryptor({ cipher, options }) {
    return createEcbEncryptor(cipher, getMutableInput(options));
  },
  createDecryptor({ cipher, options }) {
    return createEcbDecryptor(cipher, getMutableInput(options));
  },
};

function createEcbEncryptor(cipher: BlockCipher, mutableInput: boolean): Transform {
  return {
    process(input) {
      assertBlockMultiple(cipher.blockSize, input);
      const output = mutableInput ? input : new Uint8Array(input.length);
      return cipher.encrypt(input, output);
    },

    finalize(input = new Uint8Array(0)) {
      return input.length === 0 ? new Uint8Array(0) : this.process(input);
    },
  };
}

function createEcbDecryptor(cipher: BlockCipher, mutableInput: boolean): Transform {
  return {
    process(input) {
      assertBlockMultiple(cipher.blockSize, input);
      const output = mutableInput ? input : new Uint8Array(input.length);
      return cipher.decrypt(input, output);
    },

    finalize(input = new Uint8Array(0)) {
      return input.length === 0 ? new Uint8Array(0) : this.process(input);
    },
  };
}

function assertBlockMultiple(blockSize: number, input: Uint8Array): void {
  assertCoreBlockMultiple(input, blockSize, 'ECB');
}

function getMutableInput(options: unknown): boolean {
  if (typeof options !== 'object' || options === null) {
    return false;
  }
  return 'mutableInput' in options && options.mutableInput === true;
}
