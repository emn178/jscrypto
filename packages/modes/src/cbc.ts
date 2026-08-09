import {
  assertBlockMultiple as assertCoreBlockMultiple,
  assertIv,
  type BlockCipher,
  type ModeComponent,
  type PresetComponent,
  type Transform,
} from '@jscrypto/core';

export const cbc: ModeComponent<'CBC'> = {
  kind: 'mode',
  name: 'CBC',
  requiresPadding: true,
  getIvSize: (cipher) => cipher.blockSize,
  createEncryptor({ cipher, iv, options }) {
    assertIv(cipher.blockSize, iv, 'CBC');
    return createCbcEncryptor(cipher, iv, getMutableInput(options));
  },
  createDecryptor({ cipher, iv, options }) {
    assertIv(cipher.blockSize, iv, 'CBC');
    return createCbcDecryptor(cipher, iv, getMutableInput(options));
  },
};

export const cbcPreset: PresetComponent<'cbc'> = {
  kind: 'preset',
  name: 'cbc',
  components() {
    return [cbc];
  },
};

function createCbcEncryptor(cipher: BlockCipher, iv: Uint8Array, mutableInput: boolean): Transform {
  let previous = iv;

  return {
    process(input) {
      assertBlockMultiple(cipher.blockSize, input);
      const output = mutableInput ? input : new Uint8Array(input.length);

      for (let offset = 0; offset < input.length; offset += cipher.blockSize) {
        for (let index = 0; index < cipher.blockSize; index++) {
          output[offset + index] = input[offset + index] ^ previous[index];
        }
        if (cipher.encryptBlock) {
          cipher.encryptBlock(output, offset, output, offset);
        } else {
          const encrypted = output.subarray(offset, offset + cipher.blockSize);
          cipher.encrypt(encrypted, encrypted);
        }
        previous = output.subarray(offset, offset + cipher.blockSize);
      }

      return output;
    },

    finalize(input = new Uint8Array(0)) {
      return input.length === 0 ? new Uint8Array(0) : this.process(input);
    },
  };
}

function createCbcDecryptor(cipher: BlockCipher, iv: Uint8Array, mutableInput: boolean): Transform {
  let previous = iv.slice();
  let current = new Uint8Array(cipher.blockSize);

  return {
    process(input) {
      assertBlockMultiple(cipher.blockSize, input);
      const output = mutableInput ? input : new Uint8Array(input.length);

      for (let offset = 0; offset < input.length; offset += cipher.blockSize) {
        current.set(input.subarray(offset, offset + cipher.blockSize));
        if (cipher.decryptBlock) {
          cipher.decryptBlock(input, offset, output, offset);
        } else {
          cipher.decrypt(
            input.subarray(offset, offset + cipher.blockSize),
            output.subarray(offset, offset + cipher.blockSize),
          );
        }
        for (let index = 0; index < cipher.blockSize; index++) {
          output[offset + index] ^= previous[index];
        }
        const nextPrevious = previous;
        previous = current;
        current = nextPrevious;
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

function getMutableInput(options: unknown): boolean {
  if (typeof options !== 'object' || options === null) {
    return false;
  }
  return 'mutableInput' in options && options.mutableInput === true;
}
