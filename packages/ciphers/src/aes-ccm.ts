import {
  assertBytes,
  concatBytes,
  equalBytes,
  type AeadComponent,
  type AeadCreateContext,
  type AeadCreateOpenerParams,
  type AeadCreateParams,
  type AeadCreateSealerParams,
  type AeadTransform,
  type BlockCipher,
  type Transform,
} from '@jscrypto/core';

const BLOCK_SIZE = 16;
const KEY_SIZES = [16, 24, 32] as const;
const NONCE_SIZES = [7, 8, 9, 10, 11, 12, 13] as const;
const TAG_SIZES = [4, 6, 8, 10, 12, 14, 16] as const;
const DEFAULT_TAG_LENGTH = 16;
const MIN_NONCE_LENGTH = 7;
const MAX_NONCE_LENGTH = 13;
const AAD_SHORT_LIMIT = 0xff00;

export function createAesCcmComponent(): AeadComponent<'AES-CCM'> {
  return {
    kind: 'aead',
    name: 'AES-CCM',
    keySizes: KEY_SIZES,
    nonceSizes: NONCE_SIZES,
    recommendedNonceSize: 12,
    tagSizes: TAG_SIZES,
    create(params, context) {
      return createAesCcmTransform(params, context);
    },
  };
}

/** Exported for focused unit tests; not part of the public package surface. */
export function encodeCcmAad(aad: Uint8Array): Uint8Array {
  return concatBytes(encodeCcmAadLength(aad.length), aad);
}

/**
 * Encode only the CCM AAD length prefix for a given length.
 * Accepts synthetic lengths so the `0xffff` form (>= 2^32) can be unit-tested
 * without allocating multi-gigabyte AAD buffers.
 */
export function encodeCcmAadLength(aadLength: number): Uint8Array {
  if (aadLength === 0) {
    return new Uint8Array(0);
  }

  if (aadLength < AAD_SHORT_LIMIT) {
    const encoded = new Uint8Array(2);
    encoded[0] = (aadLength >>> 8) & 0xff;
    encoded[1] = aadLength & 0xff;
    return encoded;
  }

  if (aadLength < 0x100000000) {
    const encoded = new Uint8Array(6);
    encoded[0] = 0xff;
    encoded[1] = 0xfe;
    encoded[2] = (aadLength >>> 24) & 0xff;
    encoded[3] = (aadLength >>> 16) & 0xff;
    encoded[4] = (aadLength >>> 8) & 0xff;
    encoded[5] = aadLength & 0xff;
    return encoded;
  }

  const encoded = new Uint8Array(10);
  encoded[0] = 0xff;
  encoded[1] = 0xff;
  let remaining = aadLength;
  for (let i = 9; i >= 2; i--) {
    encoded[i] = remaining % 256;
    remaining = Math.floor(remaining / 256);
  }
  return encoded;
}

/**
 * Encode an unsigned integer into `byteLength` bytes at `out[offset]`.
 * Used for CCM length and counter fields.
 */
export function encodeCcmBinaryLength(
  value: number,
  byteLength: number,
  out: Uint8Array,
  offset: number,
): void {
  let remaining = value;
  for (let i = byteLength - 1; i >= 0; i--) {
    out[offset + i] = remaining % 256;
    remaining = Math.floor(remaining / 256);
  }
  if (remaining !== 0) {
    throw new RangeError('AES-CCM plaintext is too large for the nonce length.');
  }
}

function createAesCcmTransform(
  { key }: AeadCreateParams,
  context: AeadCreateContext,
): AeadTransform {
  assertBytes(key, 'AES-CCM key');
  if (key.length !== 16 && key.length !== 24 && key.length !== 32) {
    throw new Error('AES key must be 128, 192, or 256 bits.');
  }
  const cipher = context.createBlockCipher({ cipher: 'AES', key });

  return {
    createSealer({ nonce, aad, tagLength }: AeadCreateSealerParams): Transform {
      const resolvedNonce = requireNonce(nonce);
      const resolvedAad = resolveAad(aad);
      const resolvedTagLength = resolveTagLength(tagLength);
      let pendings: Uint8Array[] = [];
      let finalized = false;

      return {
        process(input) {
          assertNotFinalized(finalized);
          assertBytes(input, 'AES-CCM input');
          pendings.push(input);
          return new Uint8Array(0);
        },

        finalize(input = new Uint8Array(0)) {
          assertNotFinalized(finalized);
          if (input.length !== 0) {
            this.process(input);
          }
          finalized = true;
          const plaintext = collectPending(pendings);
          pendings = [];
          return seal(cipher, plaintext, resolvedNonce, resolvedAad, resolvedTagLength);
        },
      };
    },

    createOpener({ nonce, aad, tag, tagLength }: AeadCreateOpenerParams): Transform {
      const resolvedNonce = requireNonce(nonce);
      const resolvedAad = resolveAad(aad);
      const detachedTag = resolveOptionalTag(tag);
      const resolvedTagLength = detachedTag
        ? resolveTagLength(detachedTag.length)
        : resolveTagLength(tagLength);
      let pendings: Uint8Array[] = [];
      let finalized = false;

      return {
        process(input) {
          assertNotFinalized(finalized);
          assertBytes(input, 'AES-CCM input');
          pendings.push(input);
          return new Uint8Array(0);
        },

        finalize(input = new Uint8Array(0)) {
          assertNotFinalized(finalized);
          if (input.length !== 0) {
            this.process(input);
          }
          finalized = true;
          const buffered = collectPending(pendings);
          pendings = [];
          return open(
            cipher,
            buffered,
            resolvedNonce,
            resolvedAad,
            resolvedTagLength,
            detachedTag,
          );
        },
      };
    },
  };
}

function seal(
  cipher: BlockCipher,
  plaintext: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  tagLength: number,
): Uint8Array {
  const L = 15 - nonce.length;
  assertPlaintextLength(plaintext.length, L);

  const tag = computeTag(cipher, plaintext, nonce, aad, tagLength, L);
  const ciphertext = ctrCrypt(cipher, plaintext, nonce, L);
  const sealed = new Uint8Array(ciphertext.length + tagLength);
  sealed.set(ciphertext, 0);
  sealed.set(tag, ciphertext.length);
  return sealed;
}

function open(
  cipher: BlockCipher,
  input: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  tagLength: number,
  detachedTag: Uint8Array | undefined,
): Uint8Array {
  const L = 15 - nonce.length;
  let ciphertext: Uint8Array;
  let tag: Uint8Array;

  if (detachedTag) {
    ciphertext = input;
    tag = detachedTag;
  } else {
    if (input.length < tagLength) {
      throw new Error('AES-CCM ciphertext is shorter than the authentication tag.');
    }
    ciphertext = input.subarray(0, input.length - tagLength);
    tag = input.subarray(input.length - tagLength);
  }

  assertPlaintextLength(ciphertext.length, L);
  const plaintext = ctrCrypt(cipher, ciphertext, nonce, L);
  const expectedTag = computeTag(cipher, plaintext, nonce, aad, tagLength, L);
  if (!equalBytes(tag, expectedTag)) {
    plaintext.fill(0);
    throw new Error('AES-CCM authentication failed.');
  }
  return plaintext;
}

function computeTag(
  cipher: BlockCipher,
  plaintext: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  tagLength: number,
  L: number,
): Uint8Array {
  const mac = new Uint8Array(BLOCK_SIZE);
  const block = new Uint8Array(BLOCK_SIZE);

  buildB0(block, nonce, plaintext.length, aad.length > 0, tagLength, L);
  encryptBlock(cipher, block, 0, mac, 0);

  if (aad.length > 0) {
    const encodedAad = encodeCcmAad(aad);
    cbcMacBlocks(cipher, mac, encodedAad);
  }

  if (plaintext.length > 0) {
    cbcMacBlocks(cipher, mac, plaintext);
  }

  const s0 = new Uint8Array(BLOCK_SIZE);
  buildCounterBlock(block, nonce, 0, L);
  encryptBlock(cipher, block, 0, s0, 0);

  const tag = new Uint8Array(tagLength);
  for (let i = 0; i < tagLength; i++) {
    tag[i] = mac[i]! ^ s0[i]!;
  }
  return tag;
}

function ctrCrypt(
  cipher: BlockCipher,
  input: Uint8Array,
  nonce: Uint8Array,
  L: number,
): Uint8Array {
  if (input.length === 0) {
    return new Uint8Array(0);
  }

  const output = new Uint8Array(input.length);
  const counterBlock = new Uint8Array(BLOCK_SIZE);
  const keystream = new Uint8Array(BLOCK_SIZE);
  let counter = 1;
  let offset = 0;

  while (offset < input.length) {
    buildCounterBlock(counterBlock, nonce, counter, L);
    encryptBlock(cipher, counterBlock, 0, keystream, 0);
    const n = Math.min(BLOCK_SIZE, input.length - offset);
    for (let i = 0; i < n; i++) {
      output[offset + i] = input[offset + i]! ^ keystream[i]!;
    }
    offset += n;
    counter += 1;
  }

  return output;
}

function cbcMacBlocks(cipher: BlockCipher, mac: Uint8Array, data: Uint8Array): void {
  const block = new Uint8Array(BLOCK_SIZE);
  let offset = 0;

  while (offset < data.length) {
    const n = Math.min(BLOCK_SIZE, data.length - offset);
    block.fill(0);
    block.set(data.subarray(offset, offset + n));
    for (let i = 0; i < BLOCK_SIZE; i++) {
      block[i]! ^= mac[i]!;
    }
    encryptBlock(cipher, block, 0, mac, 0);
    offset += n;
  }
}

function buildB0(
  out: Uint8Array,
  nonce: Uint8Array,
  messageLength: number,
  hasAad: boolean,
  tagLength: number,
  L: number,
): void {
  out[0] = ((hasAad ? 1 : 0) << 6) | (((tagLength - 2) / 2) << 3) | (L - 1);
  out.set(nonce, 1);
  encodeCcmBinaryLength(messageLength, L, out, 1 + nonce.length);
}

function buildCounterBlock(
  out: Uint8Array,
  nonce: Uint8Array,
  counter: number,
  L: number,
): void {
  out.fill(0);
  out[0] = L - 1;
  out.set(nonce, 1);
  encodeCcmBinaryLength(counter, L, out, 1 + nonce.length);
}

function encryptBlock(
  cipher: BlockCipher,
  input: Uint8Array,
  inputOffset: number,
  output: Uint8Array,
  outputOffset: number,
): void {
  if (cipher.encryptBlock) {
    cipher.encryptBlock(input, inputOffset, output, outputOffset);
    return;
  }

  cipher.encrypt(
    input.subarray(inputOffset, inputOffset + cipher.blockSize),
    output.subarray(outputOffset, outputOffset + cipher.blockSize),
  );
}

function assertPlaintextLength(length: number, L: number): void {
  let remaining = length;
  for (let i = 0; i < L; i++) {
    remaining = Math.floor(remaining / 256);
  }
  if (remaining !== 0) {
    throw new RangeError('AES-CCM plaintext is too large for the nonce length.');
  }
}

function requireNonce(nonce: Uint8Array | undefined): Uint8Array {
  if (nonce === undefined) {
    throw new Error('AES-CCM requires a nonce.');
  }
  assertBytes(nonce, 'AES-CCM nonce');
  if (nonce.length < MIN_NONCE_LENGTH || nonce.length > MAX_NONCE_LENGTH) {
    throw new RangeError('AES-CCM nonce length must be between 7 and 13 bytes.');
  }
  return nonce;
}

function resolveAad(aad: Uint8Array | undefined): Uint8Array {
  if (aad === undefined) {
    return new Uint8Array(0);
  }
  assertBytes(aad, 'AES-CCM aad');
  return aad;
}

function resolveOptionalTag(tag: Uint8Array | undefined): Uint8Array | undefined {
  if (tag === undefined) {
    return undefined;
  }
  assertBytes(tag, 'AES-CCM tag');
  resolveTagLength(tag.length);
  return tag;
}

function resolveTagLength(tagLength: number | undefined): number {
  if (tagLength === undefined) {
    return DEFAULT_TAG_LENGTH;
  }
  if (
    typeof tagLength !== 'number'
    || !Number.isInteger(tagLength)
    || (TAG_SIZES as readonly number[]).indexOf(tagLength) === -1
  ) {
    throw new RangeError(
      'AES-CCM tagLength must be one of 4, 6, 8, 10, 12, 14, or 16 bytes.',
    );
  }
  return tagLength;
}

function collectPending(pendings: readonly Uint8Array[]): Uint8Array {
  if (pendings.length === 0) {
    return new Uint8Array(0);
  }
  if (pendings.length === 1) {
    return pendings[0]!;
  }
  return concatBytes(...pendings);
}

function assertNotFinalized(finalized: boolean): void {
  if (finalized) {
    throw new Error('AES-CCM transform already finalized.');
  }
}
