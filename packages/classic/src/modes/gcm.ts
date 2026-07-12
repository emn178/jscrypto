import {
  assertBytes,
  concatBytes,
  equalBytes,
  type BlockCipher,
  type ModeComponent,
  type Transform,
} from '@jscrypto/core';

export const gcm: ModeComponent<'GCM'> = {
  kind: 'mode',
  name: 'GCM',
  aead: true,
  requiredBlockSize: 16,
  requiresPadding: false,
  createEncryptor({ cipher, iv, options }) {
    return createGcmEncryptor(cipher, getNonce(iv, options), getAad(options), getTagLength(options));
  },
  createDecryptor({ cipher, iv, options }) {
    return createGcmDecryptor(cipher, getNonce(iv, options), getAad(options), getTagLength(options), getTag(options));
  },
};

const BLOCK_SIZE = 16;
const DEFAULT_TAG_LENGTH = 16;
const R_WORD = 0xe1000000;

function createGcmEncryptor(cipher: BlockCipher, nonce: Uint8Array, aad: Uint8Array, tagLength: number): Transform {
  assertGcmCipher(cipher);
  const auth = createGhash(cipher.encryptBlock(new Uint8Array(BLOCK_SIZE)));
  auth.update(aad);
  auth.pad();

  const j0 = createInitialCounter(auth.h, nonce);
  const tagMask = cipher.encryptBlock(j0);
  const counter = j0.slice();
  incrementCounter(counter);
  const xor = createCounterXor(cipher, counter);

  let ciphertextLength = 0;

  return {
    process(input) {
      const ciphertext = xor(input);
      auth.update(ciphertext);
      ciphertextLength += ciphertext.length;
      return ciphertext;
    },

    finalize(input = new Uint8Array(0)) {
      const ciphertext = input.length === 0 ? new Uint8Array(0) : this.process(input);
      const tag = createTag(auth, tagMask, aad.length, ciphertextLength, tagLength);
      return concatBytes(ciphertext, tag);
    },
  };
}

function createGcmDecryptor(
  cipher: BlockCipher,
  nonce: Uint8Array,
  aad: Uint8Array,
  tagLength: number,
  detachedTag?: Uint8Array,
): Transform {
  assertGcmCipher(cipher);
  const h = cipher.encryptBlock(new Uint8Array(BLOCK_SIZE));
  const j0 = createInitialCounter(h, nonce);
  const tagMask = cipher.encryptBlock(j0);
  let pending: Uint8Array<ArrayBufferLike> = new Uint8Array(0);

  return {
    process(input) {
      pending = concatBytes(pending, input);
      return new Uint8Array(0);
    },

    finalize(input = new Uint8Array(0)) {
      if (input.length !== 0) {
        this.process(input);
      }

      let ciphertext = pending;
      let tag = detachedTag;
      if (!tag) {
        if (pending.length < tagLength) {
          throw new Error('GCM ciphertext must include an authentication tag.');
        }
        ciphertext = new Uint8Array(pending.subarray(0, pending.length - tagLength));
        tag = new Uint8Array(pending.subarray(pending.length - tagLength));
      }

      const auth = createGhash(h);
      auth.update(aad);
      auth.pad();
      auth.update(ciphertext);
      const expectedTag = createTag(auth, tagMask, aad.length, ciphertext.length, tagLength);
      if (!equalBytes(expectedTag, tag)) {
        throw new Error('GCM authentication failed.');
      }

      const counter = j0.slice();
      incrementCounter(counter);
      const plaintext = createCounterXor(cipher, counter)(ciphertext);
      pending = new Uint8Array(0);
      return plaintext;
    },
  };
}

interface Ghash {
  readonly h: Uint8Array;
  update(input: Uint8Array): void;
  pad(): void;
  digest(aadLength: number, ciphertextLength: number): Uint8Array;
}

function createGhash(h: Uint8Array): Ghash {
  const hValue = blockToWords(h);
  let state = createZeroWords();
  let pending = new Uint8Array(0);

  function updateBlock(block: Uint8Array): void {
    state = multiplyGf128(xorWords(state, blockToWords(padBlock(block))), hValue);
  }

  return {
    h,

    update(input) {
      const data = concatBytes(pending, input);
      const processLength = data.length - (data.length % BLOCK_SIZE);
      for (let offset = 0; offset < processLength; offset += BLOCK_SIZE) {
        updateBlock(data.subarray(offset, offset + BLOCK_SIZE));
      }
      pending = data.slice(processLength);
    },

    pad() {
      if (pending.length !== 0) {
        updateBlock(pending);
        pending = new Uint8Array(0);
      }
    },

    digest(aadLength, ciphertextLength) {
      this.pad();
      updateBlock(createLengthBlock(aadLength, ciphertextLength));
      return wordsToBlock(state);
    },
  };
}

function createInitialCounter(h: Uint8Array, nonce: Uint8Array): Uint8Array {
  if (nonce.length === 0) {
    throw new Error('GCM mode requires a nonce.');
  }

  if (nonce.length === 12) {
    const j0 = new Uint8Array(BLOCK_SIZE);
    j0.set(nonce);
    j0[15] = 1;
    return j0;
  }

  const auth = createGhash(h);
  auth.update(nonce);
  return auth.digest(0, nonce.length);
}

function createCounterXor(cipher: BlockCipher, counter: Uint8Array): (input: Uint8Array) => Uint8Array {
  let keystream: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
  let position = BLOCK_SIZE;

  return (input) => {
    const output = new Uint8Array(input.length);

    for (let i = 0; i < input.length; i++) {
      if (position === BLOCK_SIZE) {
        keystream = cipher.encryptBlock(counter);
        incrementCounter(counter);
        position = 0;
      }
      output[i] = input[i] ^ keystream[position];
      position++;
    }

    return output;
  };
}

function createTag(auth: Ghash, tagMask: Uint8Array, aadLength: number, ciphertextLength: number, tagLength: number): Uint8Array {
  const tag = auth.digest(aadLength, ciphertextLength);
  for (let i = 0; i < tag.length; i++) {
    tag[i] ^= tagMask[i];
  }
  return tag.subarray(0, tagLength);
}

type Words128 = [number, number, number, number];

function createZeroWords(): Words128 {
  return [0, 0, 0, 0];
}

function multiplyGf128(x: Words128, y: Words128): Words128 {
  const z = createZeroWords();
  const v: Words128 = [y[0], y[1], y[2], y[3]];

  for (let i = 0; i < 128; i++) {
    if ((x[i >>> 5] & (0x80000000 >>> (i & 31))) !== 0) {
      xorWordsInPlace(z, v);
    }
    shiftRightAndReduce(v);
  }

  return z;
}

function shiftRightAndReduce(words: Words128): void {
  const lsb = words[3] & 1;
  words[3] = ((words[3] >>> 1) | ((words[2] & 1) << 31)) >>> 0;
  words[2] = ((words[2] >>> 1) | ((words[1] & 1) << 31)) >>> 0;
  words[1] = ((words[1] >>> 1) | ((words[0] & 1) << 31)) >>> 0;
  words[0] >>>= 1;
  if (lsb) {
    words[0] = (words[0] ^ R_WORD) >>> 0;
  }
}

function xorWords(left: Words128, right: Words128): Words128 {
  return [
    (left[0] ^ right[0]) >>> 0,
    (left[1] ^ right[1]) >>> 0,
    (left[2] ^ right[2]) >>> 0,
    (left[3] ^ right[3]) >>> 0,
  ];
}

function xorWordsInPlace(left: Words128, right: Words128): void {
  left[0] = (left[0] ^ right[0]) >>> 0;
  left[1] = (left[1] ^ right[1]) >>> 0;
  left[2] = (left[2] ^ right[2]) >>> 0;
  left[3] = (left[3] ^ right[3]) >>> 0;
}

function incrementCounter(counter: Uint8Array): void {
  const value = (
    (((counter[12] << 24) >>> 0) |
    (counter[13] << 16) |
    (counter[14] << 8) |
    counter[15]) + 1
  ) >>> 0;
  counter[12] = value >>> 24;
  counter[13] = value >>> 16;
  counter[14] = value >>> 8;
  counter[15] = value;
}

function padBlock(input: Uint8Array): Uint8Array {
  if (input.length === BLOCK_SIZE) {
    return input;
  }
  const output = new Uint8Array(BLOCK_SIZE);
  output.set(input);
  return output;
}

function createLengthBlock(aadLength: number, ciphertextLength: number): Uint8Array {
  const output = new Uint8Array(BLOCK_SIZE);
  writeBitLength64BE(aadLength, output, 0);
  writeBitLength64BE(ciphertextLength, output, 8);
  return output;
}

function writeBitLength64BE(byteLength: number, output: Uint8Array, offset: number): void {
  const high = Math.floor(byteLength / 0x20000000);
  const low = (byteLength % 0x20000000) * 8;
  writeUint32BE(high, output, offset);
  writeUint32BE(low, output, offset + 4);
}

function blockToWords(input: Uint8Array): Words128 {
  return [
    readUint32BE(input, 0),
    readUint32BE(input, 4),
    readUint32BE(input, 8),
    readUint32BE(input, 12),
  ];
}

function wordsToBlock(words: Words128): Uint8Array {
  const output = new Uint8Array(BLOCK_SIZE);
  writeUint32BE(words[0], output, 0);
  writeUint32BE(words[1], output, 4);
  writeUint32BE(words[2], output, 8);
  writeUint32BE(words[3], output, 12);
  return output;
}

function readUint32BE(input: Uint8Array, offset: number): number {
  return (
    ((input[offset] << 24) >>> 0) |
    (input[offset + 1] << 16) |
    (input[offset + 2] << 8) |
    input[offset + 3]
  ) >>> 0;
}

function writeUint32BE(value: number, output: Uint8Array, offset: number): void {
  output[offset] = value >>> 24;
  output[offset + 1] = value >>> 16;
  output[offset + 2] = value >>> 8;
  output[offset + 3] = value;
}

function getNonce(iv: Uint8Array | undefined, options: unknown): Uint8Array {
  const nonce = getOptions(options).nonce;
  if (nonce !== undefined) {
    assertBytes(nonce, 'GCM nonce');
    if (iv !== undefined) {
      throw new Error('GCM mode accepts either iv or nonce, not both.');
    }
    return nonce;
  }

  if (!iv) {
    throw new Error('GCM mode requires an IV/nonce.');
  }
  return iv;
}

function getAad(options: unknown): Uint8Array {
  const aad = getOptions(options).aad;
  if (aad === undefined) {
    return new Uint8Array(0);
  }
  assertBytes(aad, 'GCM aad');
  return aad;
}

function getTag(options: unknown): Uint8Array | undefined {
  const tag = getOptions(options).tag;
  if (tag === undefined) {
    return undefined;
  }
  assertBytes(tag, 'GCM tag');
  return tag;
}

function getTagLength(options: unknown): number {
  const tag = getTag(options);
  if (tag) {
    return tag.length;
  }

  const tagLength = getOptions(options).tagLength;
  if (tagLength === undefined) {
    return DEFAULT_TAG_LENGTH;
  }
  if (typeof tagLength !== 'number' || !Number.isInteger(tagLength) || tagLength < 4 || tagLength > BLOCK_SIZE) {
    throw new RangeError('GCM tagLength must be an integer between 4 and 16 bytes.');
  }
  return tagLength;
}

function getOptions(options: unknown): Record<string, unknown> {
  return typeof options === 'object' && options !== null ? options as Record<string, unknown> : {};
}

function assertGcmCipher(cipher: BlockCipher): void {
  if (cipher.blockSize !== BLOCK_SIZE) {
    throw new Error('GCM mode requires a 128-bit block cipher.');
  }
}
