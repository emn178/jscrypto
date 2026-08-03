import { assertIv, type BlockCipher, type ModeComponent, type Transform } from '@jscrypto/core';

export const cfb: ModeComponent<'CFB'> = {
  kind: 'mode',
  name: 'CFB',
  requiresPadding: false,
  getIvSize: (cipher) => cipher.blockSize,
  createEncryptor({ cipher, iv, options }) {
    assertIv(cipher.blockSize, iv, 'CFB');
    return createCfbEncryptor(cipher, iv, getMutableInput(options));
  },
  createDecryptor({ cipher, iv, options }) {
    assertIv(cipher.blockSize, iv, 'CFB');
    return createCfbDecryptor(cipher, iv, getMutableInput(options));
  },
};

function createCfbEncryptor(cipher: BlockCipher, iv: Uint8Array, mutableInput: boolean): Transform {
  return createCfbTransform(cipher, iv, true, mutableInput);
}

function createCfbDecryptor(cipher: BlockCipher, iv: Uint8Array, mutableInput: boolean): Transform {
  return createCfbTransform(cipher, iv, false, mutableInput);
}

function createCfbTransform(cipher: BlockCipher, iv: Uint8Array, encrypting: boolean, mutableInput: boolean): Transform {
  let feedback: Uint8Array = iv.slice();
  let nextFeedback: Uint8Array = new Uint8Array(cipher.blockSize);
  let keystream: Uint8Array = new Uint8Array(cipher.blockSize);
  let position = 0;

  return {
    process(input) {
      const output = mutableInput ? input : new Uint8Array(input.length);
      let offset = 0;

      if (position === 0) {
        for (; offset + cipher.blockSize <= input.length; offset += cipher.blockSize) {
          encryptFeedback(cipher, feedback, keystream);
          for (let index = 0; index < cipher.blockSize; index++) {
            const inputByte = input[offset + index];
            const outputByte = inputByte ^ keystream[index];
            output[offset + index] = outputByte;
            nextFeedback[index] = encrypting ? outputByte : inputByte;
          }
          const previousFeedback = feedback;
          feedback = nextFeedback;
          nextFeedback = previousFeedback;
        }
      }

      for (let i = offset; i < input.length; i++) {
        if (position === 0) {
          encryptFeedback(cipher, feedback, keystream);
        }

        const inputByte = input[i];
        const outputByte = inputByte ^ keystream[position];
        output[i] = outputByte;
        nextFeedback[position] = encrypting ? outputByte : inputByte;
        position++;

        if (position === cipher.blockSize) {
          const previousFeedback = feedback;
          feedback = nextFeedback;
          nextFeedback = previousFeedback;
          position = 0;
        }
      }

      return output;
    },

    finalize(input = new Uint8Array(0)) {
      return input.length === 0 ? new Uint8Array(0) : this.process(input);
    },
  };
}

function encryptFeedback(cipher: BlockCipher, feedback: Uint8Array, keystream: Uint8Array): void {
  if (cipher.encryptBlock) {
    cipher.encryptBlock(feedback, 0, keystream, 0);
  } else {
    cipher.encrypt(feedback, keystream);
  }
}

function getMutableInput(options: unknown): boolean {
  if (typeof options !== 'object' || options === null) {
    return false;
  }
  return 'mutableInput' in options && options.mutableInput === true;
}
