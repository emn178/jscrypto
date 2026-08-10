import {
  assertBytes,
  type AeadComponent,
  type AeadCreateContext,
  type AeadCreateOpenerParams,
  type AeadCreateParams,
  type AeadCreateSealerParams,
  type AeadTransform,
  type Transform,
} from '@jscrypto/core';

const KEY_SIZES = [16, 24, 32] as const;
const TAG_SIZES = [4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16] as const;
const DEFAULT_TAG_LENGTH = 16;
const MIN_TAG_LENGTH = 4;
const MAX_TAG_LENGTH = 16;

export function createAesGcmComponent(): AeadComponent<'AES-GCM'> {
  return {
    kind: 'aead',
    name: 'AES-GCM',
    keySizes: KEY_SIZES,
    recommendedNonceSize: 12,
    tagSizes: TAG_SIZES,
    create(params, context) {
      return createAesGcmTransform(params, context);
    },
  };
}

function createAesGcmTransform(
  { key }: AeadCreateParams,
  context: AeadCreateContext,
): AeadTransform {
  assertBytes(key, 'AES-GCM key');

  return {
    createSealer({ nonce, aad, tagLength, options }: AeadCreateSealerParams): Transform {
      return context.createEncryptor(toGcmOptions(key, {
        nonce: requireNonce(nonce),
        aad: resolveAad(aad),
        tagLength: resolveTagLength(tagLength),
        options,
      }));
    },

    createOpener({ nonce, aad, tag, tagLength, options }: AeadCreateOpenerParams): Transform {
      const detachedTag = resolveOptionalTag(tag);
      return wrapGcmOpener(context.createDecryptor(toGcmOptions(key, {
        nonce: requireNonce(nonce),
        aad: resolveAad(aad),
        tag: detachedTag,
        tagLength: detachedTag ? resolveTagLength(detachedTag.length) : resolveTagLength(tagLength),
        options,
      })));
    },
  };
}

function toGcmOptions(
  key: Uint8Array,
  {
    nonce,
    aad,
    tag,
    tagLength,
    options,
  }: {
    nonce: Uint8Array;
    aad: Uint8Array;
    tag?: Uint8Array;
    tagLength: number;
    options?: unknown;
  },
) {
  return {
    ...toRecord(options),
    cipher: 'AES',
    mode: 'GCM',
    key,
    nonce,
    aad,
    tag,
    tagLength,
  };
}

function wrapGcmOpener(opener: Transform): Transform {
  return {
    process(input) {
      return opener.process(input);
    },

    finalize(input) {
      try {
        return opener.finalize(input);
      } catch (error) {
        if (error instanceof Error && error.message === 'GCM authentication failed.') {
          throw new Error('AES-GCM authentication failed.');
        }
        throw error;
      }
    },
  };
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

function toRecord(options: unknown): Record<string, unknown> {
  return typeof options === 'object' && options !== null ? options as Record<string, unknown> : {};
}
