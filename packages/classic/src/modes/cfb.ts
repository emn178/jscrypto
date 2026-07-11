import { assertIv, type BlockCipher, type ModeComponent, type Transform } from '@crypto/core';

export const cfb: ModeComponent<'CFB'> = {
  kind: 'mode',
  name: 'CFB',
  requiresPadding: false,
  createEncryptor({ cipher, iv }) {
    assertIv(cipher.blockSize, iv, 'CFB');
    return createCfbEncryptor(cipher, iv);
  },
  createDecryptor({ cipher, iv }) {
    assertIv(cipher.blockSize, iv, 'CFB');
    return createCfbDecryptor(cipher, iv);
  },
};

function createCfbEncryptor(cipher: BlockCipher, iv: Uint8Array): Transform {
  return createCfbTransform(cipher, iv, true);
}

function createCfbDecryptor(cipher: BlockCipher, iv: Uint8Array): Transform {
  return createCfbTransform(cipher, iv, false);
}

function createCfbTransform(cipher: BlockCipher, iv: Uint8Array, encrypting: boolean): Transform {
  let feedback: Uint8Array = iv.slice();
  let nextFeedback: Uint8Array = new Uint8Array(cipher.blockSize);
  let keystream: Uint8Array = new Uint8Array(cipher.blockSize);
  let position = 0;

  return {
    process(input) {
      const output = new Uint8Array(input.length);

      for (let i = 0; i < input.length; i++) {
        if (position === 0) {
          keystream = cipher.encryptBlock(feedback);
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

    finalize(input = new Uint8Array()) {
      return input.length === 0 ? new Uint8Array() : this.process(input);
    },
  };
}
