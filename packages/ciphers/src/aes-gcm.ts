import {
  assertBytes,
  concatBytes,
  equalBytes,
  type AeadComponent,
  type AeadCreateParams,
  type AeadOpenParams,
  type AeadSealParams,
  type AeadTransform,
  type BlockCipher,
} from '@jscrypto/core';
import { gcm as nobleGcm } from '@noble/ciphers/aes.js';

const BLOCK_SIZE = 16;
const KEY_SIZES = [16, 24, 32] as const;
const TAG_SIZES = [4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16] as const;
const DEFAULT_TAG_LENGTH = 16;
const MIN_TAG_LENGTH = 4;
const MAX_TAG_LENGTH = 16;
const NOBLE_MIN_NONCE_LENGTH = 8;
const R_WORD = 0xe1000000;
const GHASH_WINDOW_BITS = 8;

export function createAesGcmComponent(
  createBlockCipher: (key: Uint8Array) => BlockCipher,
): AeadComponent<'AES-GCM'> {
  return {
    kind: 'aead',
    name: 'AES-GCM',
    keySizes: KEY_SIZES,
    recommendedNonceSize: 12,
    tagSizes: TAG_SIZES,
    create(params) {
      return createAesGcmTransform(createBlockCipher, params);
    },
  };
}

function createAesGcmTransform(
  createBlockCipher: (key: Uint8Array) => BlockCipher,
  { key }: AeadCreateParams,
): AeadTransform {
  assertBytes(key, 'AES-GCM key');
  const cipher = createBlockCipher(key);
  assertGcmCipher(cipher);

  return {
    seal({ plaintext, nonce, aad, tagLength }: AeadSealParams): Uint8Array {
      assertBytes(plaintext, 'AES-GCM plaintext');
      const resolvedNonce = requireNonce(nonce);
      const resolvedAad = resolveAad(aad);
      const resolvedTagLength = resolveTagLength(tagLength);

      if (canUseNobleFastPath(resolvedNonce, resolvedTagLength)) {
        return nobleGcm(key, resolvedNonce, resolvedAad).encrypt(plaintext);
      }

      return fallbackSeal(cipher, resolvedNonce, resolvedAad, plaintext, resolvedTagLength);
    },

    open({ ciphertext, nonce, aad, tag, tagLength }: AeadOpenParams): Uint8Array {
      assertBytes(ciphertext, 'AES-GCM ciphertext');
      const resolvedNonce = requireNonce(nonce);
      const resolvedAad = resolveAad(aad);
      const detachedTag = resolveOptionalTag(tag);
      const resolvedTagLength = detachedTag ? detachedTag.length : resolveTagLength(tagLength);

      if (canUseNobleFastPath(resolvedNonce, resolvedTagLength)) {
        const sealed = detachedTag ? concatBytes(ciphertext, detachedTag) : ciphertext;
        try {
          return nobleGcm(key, resolvedNonce, resolvedAad).decrypt(sealed);
        } catch {
          throw new Error('AES-GCM authentication failed.');
        }
      }

      let actualCiphertext = ciphertext;
      let actualTag = detachedTag;
      if (!actualTag) {
        if (ciphertext.length < resolvedTagLength) {
          throw new Error('AES-GCM ciphertext must include an authentication tag.');
        }
        actualCiphertext = ciphertext.subarray(0, ciphertext.length - resolvedTagLength);
        actualTag = ciphertext.subarray(ciphertext.length - resolvedTagLength);
      }

      return fallbackOpen(cipher, resolvedNonce, resolvedAad, actualCiphertext, actualTag, resolvedTagLength);
    },
  };
}

function canUseNobleFastPath(nonce: Uint8Array, tagLength: number): boolean {
  return nonce.length >= NOBLE_MIN_NONCE_LENGTH && tagLength === DEFAULT_TAG_LENGTH;
}

function requireNonce(nonce: Uint8Array | undefined): Uint8Array {
  if (nonce === undefined) {
    throw new Error('AES-GCM requires a nonce.');
  }
  assertBytes(nonce, 'AES-GCM nonce');
  if (nonce.length === 0) {
    throw new Error('AES-GCM requires a nonce.');
  }
  return nonce;
}

function resolveAad(aad: Uint8Array | undefined): Uint8Array {
  if (aad === undefined) {
    return new Uint8Array(0);
  }
  assertBytes(aad, 'AES-GCM aad');
  return aad;
}

function resolveOptionalTag(tag: Uint8Array | undefined): Uint8Array | undefined {
  if (tag === undefined) {
    return undefined;
  }
  assertBytes(tag, 'AES-GCM tag');
  return tag;
}

function resolveTagLength(tagLength: number | undefined): number {
  if (tagLength === undefined) {
    return DEFAULT_TAG_LENGTH;
  }
  if (
    typeof tagLength !== 'number' ||
    !Number.isInteger(tagLength) ||
    tagLength < MIN_TAG_LENGTH ||
    tagLength > MAX_TAG_LENGTH
  ) {
    throw new RangeError('AES-GCM tagLength must be an integer between 4 and 16 bytes.');
  }
  return tagLength;
}

function assertGcmCipher(cipher: BlockCipher): void {
  if (cipher.blockSize !== BLOCK_SIZE) {
    throw new Error('AES-GCM requires a 128-bit block cipher.');
  }
}

// --- GCM compatibility fallback (short nonce and/or truncated tag) ---
//
// This is a one-shot port of the chunked GCM primitives in
// `packages/modes/src/gcm.ts`, kept intentionally separate so `@jscrypto/ciphers`
// does not depend on `@jscrypto/modes`.

function fallbackSeal(
  cipher: BlockCipher,
  nonce: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
  tagLength: number,
): Uint8Array {
  const h = encryptRawBlock(cipher, new Uint8Array(BLOCK_SIZE));
  const auth = createGhash(h);
  auth.updateFinal(aad);

  const j0 = createInitialCounter(h, nonce);
  const tagMask = encryptRawBlock(cipher, j0);
  const counter = j0.slice();
  incrementCounter(counter);
  const ciphertext = createCounterXor(cipher, counter)(plaintext);
  auth.updateFinal(ciphertext);

  const tag = createTag(auth, tagMask, aad.length, ciphertext.length, tagLength);
  return concatBytes(ciphertext, tag);
}

function fallbackOpen(
  cipher: BlockCipher,
  nonce: Uint8Array,
  aad: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
  tagLength: number,
): Uint8Array {
  const h = encryptRawBlock(cipher, new Uint8Array(BLOCK_SIZE));
  const j0 = createInitialCounter(h, nonce);
  const tagMask = encryptRawBlock(cipher, j0);

  const auth = createGhash(h);
  auth.updateFinal(aad);
  auth.updateFinal(ciphertext);
  const expectedTag = createTag(auth, tagMask, aad.length, ciphertext.length, tagLength);
  if (!equalBytes(expectedTag, tag)) {
    throw new Error('AES-GCM authentication failed.');
  }

  const counter = j0.slice();
  incrementCounter(counter);
  return createCounterXor(cipher, counter)(ciphertext);
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

function createCounterXor(cipher: BlockCipher, counter: Uint8Array): (input: Uint8Array) => Uint8Array {
  return (input) => {
    const output = new Uint8Array(input.length);
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
