import { assertIv, type BlockCipher, type ModeComponent, type Transform } from '@jscrypto/core';

export const ofb: ModeComponent<'OFB'> = {
  kind: 'mode',
  name: 'OFB',
  requiresPadding: false,
  getIvSize: (cipher) => cipher.blockSize,
  createEncryptor({ cipher, iv, options }) {
    assertIv(cipher.blockSize, iv, 'OFB');
    return createOfbTransform(cipher, iv, getMutableInput(options));
  },
  createDecryptor({ cipher, iv, options }) {
    assertIv(cipher.blockSize, iv, 'OFB');
    return createOfbTransform(cipher, iv, getMutableInput(options));
  },
};

function createOfbTransform(cipher: BlockCipher, iv: Uint8Array, mutableInput: boolean): Transform {
  let feedback: Uint8Array = iv.slice();
  let keystream: Uint8Array = new Uint8Array(cipher.blockSize);
  let position = cipher.blockSize;

  return {
    process(input) {
      const output = mutableInput ? input : new Uint8Array(input.length);
      let offset = 0;

      if (position === cipher.blockSize) {
        for (; offset + cipher.blockSize <= input.length; offset += cipher.blockSize) {
          encryptFeedback(cipher, feedback, keystream);
          feedback.set(keystream);
          for (let index = 0; index < cipher.blockSize; index++) {
            output[offset + index] = input[offset + index] ^ keystream[index];
          }
        }
      }

      for (let i = offset; i < input.length; i++) {
        if (position === cipher.blockSize) {
          encryptFeedback(cipher, feedback, keystream);
          feedback.set(keystream);
          position = 0;
        }

        output[i] = input[i] ^ keystream[position];
        position++;
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
