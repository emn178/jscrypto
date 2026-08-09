import {
  assertBytes,
  concatBytes,
  equalBytes,
  type BlockCipher,
  type ModeComponent,
  type PresetComponent,
  type Transform,
} from '@jscrypto/core';

export const gcm: ModeComponent<'GCM'> = {
  kind: 'mode',
  name: 'GCM',
  requiresPadding: false,
  getIvSize: () => 0,
  createEncryptor({ cipher, iv, options }) {
    return createGcmEncryptor(cipher, getNonce(iv, options), getAad(options), getTagLength(options), getMutableInput(options));
  },
  createDecryptor({ cipher, iv, options }) {
    return createGcmDecryptor(cipher, getNonce(iv, options), getAad(options), getTagLength(options), getTag(options), getMutableInput(options));
  },
};

export const gcmPreset: PresetComponent<'gcm'> = {
  kind: 'preset',
  name: 'gcm',
  components() {
    return [gcm];
  },
};

const BLOCK_SIZE = 16;
const DEFAULT_TAG_LENGTH = 16;
const R_WORD = 0xe1000000;
const GHASH_WINDOW_BITS = 8;

function createGcmEncryptor(
  cipher: BlockCipher,
  nonce: Uint8Array,
  aad: Uint8Array,
  tagLength: number,
  mutableInput: boolean,
): Transform {
  assertGcmCipher(cipher);
  const auth = createGhash(encryptRawBlock(cipher, new Uint8Array(BLOCK_SIZE)));
  auth.updateFinal(aad);

  const j0 = createInitialCounter(auth.h, nonce);
  const tagMask = encryptRawBlock(cipher, j0);
  const counter = j0.slice();
  incrementCounter(counter);
  const xor = createCounterXor(cipher, counter);

  let ciphertextLength = 0;
  let pendingPlaintext = new Uint8Array(0);

  function encryptPlaintext(input: Uint8Array, final = false, output?: Uint8Array): Uint8Array {
    if (input.length === 0) {
      return new Uint8Array(0);
    }
    const ciphertext = xor(input, output);
    if (final) {
      auth.updateFinal(ciphertext);
    } else {
      auth.update(ciphertext);
    }
    ciphertextLength += ciphertext.length;
    return ciphertext;
  }

  return {
    process(input) {
      if (pendingPlaintext.length) {
        input = concatBytes(pendingPlaintext, input);
      }
      const fullLength = input.length - (input.length % BLOCK_SIZE);
      pendingPlaintext = fullLength === input.length ? new Uint8Array(0) : input.slice(fullLength);
      if (!fullLength) {
        return new Uint8Array(0);
      }
      const fullInput = pendingPlaintext.length ? input.subarray(0, fullLength) : input;
      return encryptPlaintext(fullInput, false, mutableInput ? fullInput : undefined);
    },

    finalize(input = new Uint8Array(0)) {
      const ciphertext = input.length === 0 ? new Uint8Array(0) : this.process(input);
      const finalCiphertext = encryptPlaintext(pendingPlaintext, true, mutableInput ? pendingPlaintext : undefined);
      pendingPlaintext = new Uint8Array(0);
      const tag = createTag(auth, tagMask, aad.length, ciphertextLength, tagLength);
      return concatBytes(ciphertext, finalCiphertext, tag);
    },
  };
}

function createGcmDecryptor(
  cipher: BlockCipher,
  nonce: Uint8Array,
  aad: Uint8Array,
  tagLength: number,
  detachedTag?: Uint8Array,
  mutableInput = false,
): Transform {
  assertGcmCipher(cipher);
  const h = encryptRawBlock(cipher, new Uint8Array(BLOCK_SIZE));
  const j0 = createInitialCounter(h, nonce);
  const tagMask = encryptRawBlock(cipher, j0);
  let pendings: Uint8Array<ArrayBufferLike>[] = [];

  return {
    process(input) {
      pendings.push(input);
      return new Uint8Array(0);
    },

    finalize(input = new Uint8Array(0)) {
      if (input.length !== 0) {
        this.process(input);
      }

      const pending = pendings.length === 0
        ? new Uint8Array(0)
        : pendings.length === 1
          ? pendings[0]
          : concatBytes(...pendings);
      let ciphertext = pending;
      let tag = detachedTag;
      if (!tag) {
        if (pending.length < tagLength) {
          throw new Error('GCM ciphertext must include an authentication tag.');
        }
        ciphertext = pending.subarray(0, pending.length - tagLength);
        tag = pending.subarray(pending.length - tagLength);
      }

      const auth = createGhash(h);
      auth.updateFinal(aad);
      auth.updateFinal(ciphertext);
      const expectedTag = createTag(auth, tagMask, aad.length, ciphertext.length, tagLength);
      if (!equalBytes(expectedTag, tag)) {
        throw new Error('GCM authentication failed.');
      }

      const counter = j0.slice();
      incrementCounter(counter);
      const plaintext = createCounterXor(cipher, counter)(ciphertext, mutableInput ? ciphertext : undefined);
      pendings = [];
      return plaintext;
    },
  };
}

interface Ghash {
  readonly h: Uint8Array;
  update(input: Uint8Array): void;
  updateFinal(input: Uint8Array): void;
  digest(aadLength: number, ciphertextLength: number): Uint8Array;
}

function createGhash(h: Uint8Array): Ghash {
  const table = createGhashTable(blockToWords(h), GHASH_WINDOW_BITS);
  const windowSize = 1 << GHASH_WINDOW_BITS;
  let state = createZeroWords();

  function updateWords(w0: number, w1: number, w2: number, w3: number): void {
    state = multiplyGf128Window([
      (state[0] ^ w0) >>> 0,
      (state[1] ^ w1) >>> 0,
      (state[2] ^ w2) >>> 0,
      (state[3] ^ w3) >>> 0,
    ], table, windowSize);
  }

  function updateBlock(input: Uint8Array, offset: number): void {
    updateWords(
      readUint32BE(input, offset),
      readUint32BE(input, offset + 4),
      readUint32BE(input, offset + 8),
      readUint32BE(input, offset + 12),
    );
  }

  function updatePartialBlock(input: Uint8Array): void {
    updateWords(
      readUint32BEPadded(input, 0),
      readUint32BEPadded(input, 4),
      readUint32BEPadded(input, 8),
      readUint32BEPadded(input, 12),
    );
  }

  return {
    h,

    update(input) {
      for (let offset = 0; offset < input.length; offset += BLOCK_SIZE) {
        updateBlock(input, offset);
      }
    },

    updateFinal(input) {
      const fullLength = input.length - (input.length % BLOCK_SIZE);
      for (let offset = 0; offset < fullLength; offset += BLOCK_SIZE) {
        updateBlock(input, offset);
      }
      if (fullLength !== input.length) {
        updatePartialBlock(input.subarray(fullLength));
      }
    },

    digest(aadLength, ciphertextLength) {
      updateBlock(createLengthBlock(aadLength, ciphertextLength), 0);
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
  auth.updateFinal(nonce);
  return auth.digest(0, nonce.length);
}

function createCounterXor(cipher: BlockCipher, counter: Uint8Array): (input: Uint8Array, output?: Uint8Array) => Uint8Array {
  return (input, target) => {
    const output = target ?? new Uint8Array(input.length);
    if (input.length !== 0) {
      const blocks = Math.ceil(input.length / BLOCK_SIZE);
      const keystream = new Uint8Array(blocks * BLOCK_SIZE);
      for (let offset = 0; offset < keystream.length; offset += BLOCK_SIZE) {
        keystream.set(counter, offset);
        incrementCounter(counter);
      }

      cipher.encrypt(keystream, keystream);
      for (let i = 0; i < input.length; i++) {
        output[i] = input[i] ^ keystream[i];
      }
    }

    return output;
  };
}

function encryptRawBlock(cipher: BlockCipher, input: Uint8Array): Uint8Array {
  const output = new Uint8Array(BLOCK_SIZE);
  return cipher.encrypt(input, output);
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

// Adapted from @noble/ciphers' GHASH window-table approach (MIT).
function createGhashTable(h: Words128, windowBits: number): Uint32Array {
  const windowSize = 1 << windowBits;
  const windows = 128 / windowBits;
  const doubled: Words128[] = [];
  const value: Words128 = [h[0], h[1], h[2], h[3]];

  for (let bit = 0; bit < 128; bit++) {
    doubled.push([value[0], value[1], value[2], value[3]]);
    shiftRightAndReduce(value);
  }

  const table = new Uint32Array(windows * windowSize * 4);
  for (let window = 0; window < windows; window++) {
    for (let selector = 0; selector < windowSize; selector++) {
      const item = createZeroWords();
      for (let bit = 0; bit < windowBits; bit++) {
        if (((selector >>> (windowBits - bit - 1)) & 1) !== 0) {
          xorWordsInPlace(item, doubled[(window * windowBits) + bit]);
        }
      }
      const offset = ((window * windowSize) + selector) * 4;
      table[offset] = item[0];
      table[offset + 1] = item[1];
      table[offset + 2] = item[2];
      table[offset + 3] = item[3];
    }
  }
  return table;
}

function multiplyGf128Window(input: Words128, table: Uint32Array, windowSize: number): Words128 {
  const output = createZeroWords();
  const mask = windowSize - 1;
  const windows = 128 / GHASH_WINDOW_BITS;

  for (let window = 0; window < windows; window++) {
    const bitOffset = window * GHASH_WINDOW_BITS;
    const word = bitOffset >>> 5;
    const shift = 32 - GHASH_WINDOW_BITS - (bitOffset & 31);
    const selector = (input[word] >>> shift) & mask;
    if (selector !== 0) {
      const tableOffset = ((window * windowSize) + selector) * 4;
      output[0] = (output[0] ^ table[tableOffset]) >>> 0;
      output[1] = (output[1] ^ table[tableOffset + 1]) >>> 0;
      output[2] = (output[2] ^ table[tableOffset + 2]) >>> 0;
      output[3] = (output[3] ^ table[tableOffset + 3]) >>> 0;
    }
  }
  return output;
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

function readUint32BEPadded(input: Uint8Array, offset: number): number {
  return (
    (((input[offset] ?? 0) << 24) >>> 0) |
    ((input[offset + 1] ?? 0) << 16) |
    ((input[offset + 2] ?? 0) << 8) |
    (input[offset + 3] ?? 0)
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

function getMutableInput(options: unknown): boolean {
  if (typeof options !== 'object' || options === null) {
    return false;
  }
  return 'mutableInput' in options && options.mutableInput === true;
}

function assertGcmCipher(cipher: BlockCipher): void {
  if (cipher.blockSize !== BLOCK_SIZE) {
    throw new Error('GCM mode requires a 128-bit block cipher.');
  }
}
