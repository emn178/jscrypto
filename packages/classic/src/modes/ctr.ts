import { assertIv, type BlockCipher, type ModeComponent, type Transform } from '@jscrypto/core';

export const ctr: ModeComponent<'CTR'> = {
  kind: 'mode',
  name: 'CTR',
  requiresPadding: false,
  createEncryptor({ cipher, iv }) {
    assertIv(cipher.blockSize, iv, 'CTR');
    return createCtrTransform(cipher, iv);
  },
  createDecryptor({ cipher, iv }) {
    assertIv(cipher.blockSize, iv, 'CTR');
    return createCtrTransform(cipher, iv);
  },
};

function createCtrTransform(cipher: BlockCipher, iv: Uint8Array): Transform {
  const counter = iv.slice();
  let keystream: Uint8Array = new Uint8Array(cipher.blockSize);
  let position = cipher.blockSize;

  return {
    process(input) {
      const output = new Uint8Array(input.length);

      for (let i = 0; i < input.length; i++) {
        if (position === cipher.blockSize) {
          keystream = cipher.encryptBlock(counter);
          incrementCounter(counter);
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

function incrementCounter(counter: Uint8Array): void {
  for (let i = counter.length - 1; i >= 0; i--) {
    counter[i] = (counter[i] + 1) & 0xff;
    if (counter[i] !== 0) {
      return;
    }
  }
}
