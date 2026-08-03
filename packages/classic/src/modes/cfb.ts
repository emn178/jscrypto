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

      for (let i = 0; i < input.length; i++) {
        if (position === 0) {
          cipher.encrypt(feedback, keystream);
        }

        const inputByte = input[i];
        const outputByte = inputByte ^ keystream[position];
        output[i] = outputByte;
        nextFeedback[position] = encrypting ? outputByte : inputByte;
        position++;

        if (position === cipher.blockSize) {
          feedback = nextFeedback;
          nextFeedback = new Uint8Array(cipher.blockSize);
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

function getMutableInput(options: unknown): boolean {
  if (typeof options !== 'object' || options === null) {
    return false;
  }
  return 'mutableInput' in options && options.mutableInput === true;
}
