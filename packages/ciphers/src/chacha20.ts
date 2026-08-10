import {
  assertBytes,
  concatBytes,
  type AeadComponent,
  type AeadTransform,
  type CipherComponent,
  type PresetComponent,
  type StreamCipherComponent,
  type StreamCipherTransformParams,
  type Transform,
} from '@jscrypto/core';
import {
  chacha20 as nobleChaCha20,
  chacha20poly1305 as nobleChaCha20Poly1305,
  xchacha20 as nobleXChaCha20,
  xchacha20poly1305 as nobleXChaCha20Poly1305,
} from '@noble/ciphers/chacha.js';

const KEY_BYTES = 32;
const CHACHA20_NONCE_BYTES = 12;
const XCHACHA20_NONCE_BYTES = 24;
const TAG_BYTES = 16;
const STREAM_BLOCK_BYTES = 64;
const MAX_COUNTER = 0xffffffff; // exclusive upper bound, matching @noble/ciphers

export const chacha20: StreamCipherComponent<'ChaCha20'> = {
  kind: 'cipher',
  name: 'ChaCha20',
  type: 'stream',
  keySizes: [KEY_BYTES],
  createEncryptor(params) {
    return createStreamTransform(params, 'ChaCha20');
  },
  createDecryptor(params) {
    return createStreamTransform(params, 'ChaCha20');
  },
};

export const xchacha20: StreamCipherComponent<'XChaCha20'> = {
  kind: 'cipher',
  name: 'XChaCha20',
  type: 'stream',
  keySizes: [KEY_BYTES],
  createEncryptor(params) {
    return createStreamTransform(params, 'XChaCha20');
  },
  createDecryptor(params) {
    return createStreamTransform(params, 'XChaCha20');
  },
};

export const chacha20Poly1305: AeadComponent<'ChaCha20-Poly1305'> = {
  kind: 'aead',
  name: 'ChaCha20-Poly1305',
  keySizes: [KEY_BYTES],
  nonceSizes: [CHACHA20_NONCE_BYTES],
  recommendedNonceSize: CHACHA20_NONCE_BYTES,
  tagSizes: [TAG_BYTES],
  create({ key }) {
    return createAeadTransform(key, 'ChaCha20-Poly1305');
  },
};

export const xchacha20Poly1305: AeadComponent<'XChaCha20-Poly1305'> = {
  kind: 'aead',
  name: 'XChaCha20-Poly1305',
  keySizes: [KEY_BYTES],
  nonceSizes: [XCHACHA20_NONCE_BYTES],
  recommendedNonceSize: XCHACHA20_NONCE_BYTES,
  tagSizes: [TAG_BYTES],
  create({ key }) {
    return createAeadTransform(key, 'XChaCha20-Poly1305');
  },
};

export const allChaCha20Components: readonly (CipherComponent | AeadComponent)[] = [
  chacha20,
  xchacha20,
  chacha20Poly1305,
  xchacha20Poly1305,
];

export const chacha20Preset: PresetComponent<'chacha20'> = {
  kind: 'preset',
  name: 'chacha20',
  components() {
    return allChaCha20Components;
  },
};

type StreamAlgorithm = 'ChaCha20' | 'XChaCha20';
type AeadAlgorithm = 'ChaCha20-Poly1305' | 'XChaCha20-Poly1305';

function createStreamTransform(
  params: StreamCipherTransformParams,
  algorithm: StreamAlgorithm,
): Transform {
  assertUnsupportedBlockOptions(params.options, algorithm);
  assertBytes(params.key, `${algorithm} key`);
  assertKey(params.key, algorithm);
  const options = asRecord(params.options);
  const nonce = requireNonce(options, algorithm);
  let blockCounter = resolveCounter(options.counter, algorithm);
  let keystream: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
  let keystreamOffset = 0;
  let finalized = false;

  const xorChunk = (input: Uint8Array): Uint8Array => {
    if (input.length === 0) {
      return new Uint8Array(0);
    }

    const output = new Uint8Array(input.length);
    let inputOffset = 0;

    while (inputOffset < input.length) {
      if (keystreamOffset >= keystream.length) {
        const remaining = input.length - inputOffset;
        const generateLength = Math.ceil(remaining / STREAM_BLOCK_BYTES) * STREAM_BLOCK_BYTES;
        keystream = applyStream(
          algorithm,
          params.key,
          nonce,
          new Uint8Array(generateLength),
          blockCounter,
        );
        blockCounter += generateLength / STREAM_BLOCK_BYTES;
        keystreamOffset = 0;
      }

      const n = Math.min(input.length - inputOffset, keystream.length - keystreamOffset);
      for (let i = 0; i < n; i++) {
        output[inputOffset + i] = (input[inputOffset + i] as number) ^ (keystream[keystreamOffset + i] as number);
      }
      inputOffset += n;
      keystreamOffset += n;
    }

    return output;
  };

  return {
    process(input) {
      assertNotFinalized(finalized);
      assertBytes(input, `${algorithm} input`);
      return xorChunk(input);
    },
    finalize(input = new Uint8Array(0)) {
      assertNotFinalized(finalized);
      assertBytes(input, `${algorithm} input`);
      finalized = true;
      const output = input.length === 0 ? new Uint8Array(0) : xorChunk(input);
      keystream = new Uint8Array(0);
      keystreamOffset = 0;
      return output;
    },
  };
}

function createAeadTransform(key: Uint8Array, algorithm: AeadAlgorithm): AeadTransform {
  assertBytes(key, `${algorithm} key`);
  assertKey(key, algorithm);

  return {
    seal({ plaintext, nonce, aad, tagLength }) {
      assertBytes(plaintext, `${algorithm} input`);
      const resolvedNonce = requireAeadNonce(nonce, algorithm);
      const resolvedAad = resolveAad(aad, algorithm);
      assertTagLength(tagLength, algorithm);
      const cipher = createNobleAead(algorithm, key, resolvedNonce, resolvedAad);
      return cipher.encrypt(plaintext);
    },
    open({ ciphertext, nonce, aad, tag, tagLength }) {
      assertBytes(ciphertext, `${algorithm} input`);
      const resolvedNonce = requireAeadNonce(nonce, algorithm);
      const resolvedAad = resolveAad(aad, algorithm);
      const detachedTag = resolveOptionalTag(tag, algorithm);
      // When a detached tag is present, tag.length wins and tagLength is ignored.
      if (detachedTag === undefined) {
        assertTagLength(tagLength, algorithm);
      }
      const sealed = resolveSealedInput(ciphertext, detachedTag, algorithm);
      const cipher = createNobleAead(algorithm, key, resolvedNonce, resolvedAad);
      try {
        return cipher.decrypt(sealed);
      } catch {
        throw new Error(`${algorithm} authentication failed.`);
      }
    },
  };
}

function applyStream(
  algorithm: StreamAlgorithm,
  key: Uint8Array,
  nonce: Uint8Array,
  data: Uint8Array,
  counter: number,
): Uint8Array {
  if (algorithm === 'ChaCha20') {
    return nobleChaCha20(key, nonce, data, undefined, counter);
  }
  return nobleXChaCha20(key, nonce, data, undefined, counter);
}

function createNobleAead(
  algorithm: AeadAlgorithm,
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
) {
  if (algorithm === 'ChaCha20-Poly1305') {
    return nobleChaCha20Poly1305(key, nonce, aad);
  }
  return nobleXChaCha20Poly1305(key, nonce, aad);
}

function resolveSealedInput(
  ciphertext: Uint8Array,
  tag: Uint8Array | undefined,
  algorithm: AeadAlgorithm,
): Uint8Array {
  if (tag === undefined) {
    if (ciphertext.length < TAG_BYTES) {
      throw new Error(`${algorithm} ciphertext must include a 128-bit authentication tag.`);
    }
    return ciphertext;
  }
  assertTag(tag, algorithm);
  return concatBytes(ciphertext, tag);
}

function requireNonce(options: Record<string, unknown>, algorithm: StreamAlgorithm): Uint8Array {
  const nonce = options.nonce;
  if (nonce === undefined) {
    throw new Error(`${algorithm} requires a nonce.`);
  }
  assertBytes(nonce, `${algorithm} nonce`);
  assertNonce(nonce, algorithm);
  return nonce;
}

function requireAeadNonce(nonce: Uint8Array | undefined, algorithm: AeadAlgorithm): Uint8Array {
  if (nonce === undefined) {
    throw new Error(`${algorithm} requires a nonce.`);
  }
  assertBytes(nonce, `${algorithm} nonce`);
  assertNonce(nonce, algorithm);
  return nonce;
}

function resolveOptionalTag(tag: unknown, algorithm: AeadAlgorithm): Uint8Array | undefined {
  if (tag === undefined) {
    return undefined;
  }
  assertBytes(tag, `${algorithm} tag`);
  assertTag(tag, algorithm);
  return tag;
}

function resolveAad(aad: unknown, algorithm: AeadAlgorithm): Uint8Array {
  if (aad === undefined) {
    return new Uint8Array(0);
  }
  assertBytes(aad, `${algorithm} aad`);
  return aad;
}

function assertTagLength(tagLength: number | undefined, algorithm: AeadAlgorithm): void {
  if (tagLength !== undefined && tagLength !== TAG_BYTES) {
    throw new Error(`${algorithm} tagLength must be 16 bytes.`);
  }
}

function resolveCounter(counter: unknown, algorithm: StreamAlgorithm): number {
  if (counter === undefined) {
    return 0;
  }
  if (typeof counter !== 'number' || !Number.isInteger(counter) || counter < 0 || counter >= MAX_COUNTER) {
    throw new RangeError(`${algorithm} counter must be a 32-bit unsigned integer.`);
  }
  return counter;
}

function assertKey(key: Uint8Array, algorithm: string): void {
  if (key.length !== KEY_BYTES) {
    throw new Error(`${algorithm} key must be 256 bits.`);
  }
}

function assertNonce(nonce: Uint8Array, algorithm: StreamAlgorithm | AeadAlgorithm): void {
  if (algorithm === 'ChaCha20' || algorithm === 'ChaCha20-Poly1305') {
    if (nonce.length !== CHACHA20_NONCE_BYTES) {
      throw new Error(`${algorithm} nonce must be 96 bits.`);
    }
    return;
  }
  if (nonce.length !== XCHACHA20_NONCE_BYTES) {
    throw new Error(`${algorithm} nonce must be 192 bits.`);
  }
}

function assertTag(tag: Uint8Array, algorithm: AeadAlgorithm): void {
  if (tag.length !== TAG_BYTES) {
    throw new Error(`${algorithm} tag must be 128 bits.`);
  }
}

function assertUnsupportedBlockOptions(options: unknown, algorithm: string): void {
  const record = asRecord(options);
  if (Object.prototype.hasOwnProperty.call(record, 'mode') && record.mode !== undefined) {
    throw new Error(`${algorithm} does not support mode.`);
  }
  if (Object.prototype.hasOwnProperty.call(record, 'padding') && record.padding !== undefined) {
    throw new Error(`${algorithm} does not support padding.`);
  }
}

function asRecord(options: unknown): Record<string, unknown> {
  if (typeof options === 'object' && options !== null) {
    return options as Record<string, unknown>;
  }
  return {};
}

function assertNotFinalized(finalized: boolean): void {
  if (finalized) {
    throw new Error('Transform is already finalized.');
  }
}
