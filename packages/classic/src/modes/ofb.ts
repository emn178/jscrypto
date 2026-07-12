import { assertIv, type BlockCipher, type ModeComponent, type Transform } from '@jscrypto/core';

export const ofb: ModeComponent<'OFB'> = {
  kind: 'mode',
  name: 'OFB',
  requiresPadding: false,
  createEncryptor({ cipher, iv }) {
    assertIv(cipher.blockSize, iv, 'OFB');
    return createOfbTransform(cipher, iv);
  },
  createDecryptor({ cipher, iv }) {
    assertIv(cipher.blockSize, iv, 'OFB');
    return createOfbTransform(cipher, iv);
  },
};

function createOfbTransform(cipher: BlockCipher, iv: Uint8Array): Transform {
  let feedback: Uint8Array = iv.slice();
  let keystream: Uint8Array = new Uint8Array(cipher.blockSize);
  let position = cipher.blockSize;

  return {
    process(input) {
      const output = new Uint8Array(input.length);

      for (let i = 0; i < input.length; i++) {
        if (position === cipher.blockSize) {
          feedback = cipher.encryptBlock(feedback);
          keystream = feedback;
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
