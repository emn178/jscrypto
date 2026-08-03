import { assertIv, type BlockCipher, type ModeComponent, type Transform } from '@jscrypto/core';

export const cfb: ModeComponent<'CFB'> = {
  kind: 'mode',
  name: 'CFB',
  requiresPadding: false,
  getIvSize: (cipher) => cipher.blockSize,
  createEncryptor({ cipher, iv, options }) {
    assertIv(cipher.blockSize, iv, 'CFB');
    return createCfbEncryptor(cipher, iv, getInplace(options));
  },
  createDecryptor({ cipher, iv, options }) {
    assertIv(cipher.blockSize, iv, 'CFB');
    return createCfbDecryptor(cipher, iv, getInplace(options));
  },
};

function createCfbEncryptor(cipher: BlockCipher, iv: Uint8Array, inplace: boolean): Transform {
  return createCfbTransform(cipher, iv, true, inplace);
}

function createCfbDecryptor(cipher: BlockCipher, iv: Uint8Array, inplace: boolean): Transform {
  return createCfbTransform(cipher, iv, false, inplace);
}

function createCfbTransform(cipher: BlockCipher, iv: Uint8Array, encrypting: boolean, inplace: boolean): Transform {
  let feedback: Uint8Array = iv.slice();
  let nextFeedback: Uint8Array = new Uint8Array(cipher.blockSize);
  let keystream: Uint8Array = new Uint8Array(cipher.blockSize);
  let position = 0;

  return {
    process(input) {
      const output = inplace ? input : new Uint8Array(input.length);

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

function getInplace(options: unknown): boolean {
  return typeof options === 'object' && options !== null && 'inplace' in options && options.inplace === true;
}
