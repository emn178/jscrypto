import { assertIv, type BlockCipher, type ModeComponent, type PresetComponent, type Transform } from '@jscrypto/core';

export const ctr: ModeComponent<'CTR'> = {
  kind: 'mode',
  name: 'CTR',
  requiresPadding: false,
  getIvSize: (cipher) => cipher.blockSize,
  createEncryptor({ cipher, iv, options }) {
    assertIv(cipher.blockSize, iv, 'CTR');
    return createCtrTransform(cipher, iv, getMutableInput(options));
  },
  createDecryptor({ cipher, iv, options }) {
    assertIv(cipher.blockSize, iv, 'CTR');
    return createCtrTransform(cipher, iv, getMutableInput(options));
  },
};

export const ctrPreset: PresetComponent<'ctr'> = {
  kind: 'preset',
  name: 'ctr',
  components() {
    return [ctr];
  },
};

function createCtrTransform(cipher: BlockCipher, iv: Uint8Array, mutableInput: boolean): Transform {
  const counter = iv.slice();
  let keystream: Uint8Array = new Uint8Array(cipher.blockSize);
  let position = cipher.blockSize;

  return {
    process(input) {
      const output = mutableInput ? input : new Uint8Array(input.length);
      let offset = 0;

      if (position === cipher.blockSize) {
        for (; offset + cipher.blockSize <= input.length; offset += cipher.blockSize) {
          encryptCounter(cipher, counter, keystream);
          incrementCounter(counter);
          for (let index = 0; index < cipher.blockSize; index++) {
            output[offset + index] = input[offset + index] ^ keystream[index];
          }
        }
      }

      for (let i = offset; i < input.length; i++) {
        if (position === cipher.blockSize) {
          encryptCounter(cipher, counter, keystream);
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

function encryptCounter(cipher: BlockCipher, counter: Uint8Array, keystream: Uint8Array): void {
  if (cipher.encryptBlock) {
    cipher.encryptBlock(counter, 0, keystream, 0);
  } else {
    cipher.encrypt(counter, keystream);
  }
}

function incrementCounter(counter: Uint8Array): void {
  for (let i = counter.length - 1; i >= 0; i--) {
    counter[i] = (counter[i] + 1) & 0xff;
    if (counter[i] !== 0) {
      return;
    }
  }
}

function getMutableInput(options: unknown): boolean {
  if (typeof options !== 'object' || options === null) {
    return false;
  }
  return 'mutableInput' in options && options.mutableInput === true;
}
