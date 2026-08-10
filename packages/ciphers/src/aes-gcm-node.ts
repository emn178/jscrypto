import {
  assertBytes,
  concatBytes,
  type AeadComponent,
  type AeadCreateParams,
  type AeadOpenParams,
  type AeadSealParams,
  type AeadTransform,
  type BlockCipher,
} from '@jscrypto/core';
import { createCipheriv, createDecipheriv } from 'node:crypto';
import { createAesGcmComponent } from './aes-gcm.js';

const KEY_SIZES = [16, 24, 32] as const;
const TAG_SIZES = [4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16] as const;
const DEFAULT_TAG_LENGTH = 16;
const MIN_TAG_LENGTH = 4;
const MAX_TAG_LENGTH = 16;

/**
 * OpenSSL/Node AES-GCM auth tag lengths. Lengths 5–7 and 9–11 are rejected by
 * Node and must use the JS compatibility implementation instead.
 */
const NODE_NATIVE_TAG_LENGTHS = new Set([4, 8, 12, 13, 14, 15, 16]);

/**
 * Node.js AES-GCM AEAD component.
 * Uses `node:crypto` `aes-*-gcm` for supported tag lengths; falls back to the
 * shared JS AES-GCM implementation for OpenSSL-unsupported lengths so the
 * public 4–16 tagLength contract stays intact.
 */
export function createNodeAesGcmComponent(
  createBlockCipher: (key: Uint8Array) => BlockCipher,
): AeadComponent<'AES-GCM'> {
  let jsCompat: AeadComponent<'AES-GCM'> | undefined;

  return {
    kind: 'aead',
    name: 'AES-GCM',
    keySizes: KEY_SIZES,
    recommendedNonceSize: 12,
    tagSizes: TAG_SIZES,
    create(params) {
      const native = createNodeNativeTransform(params);
      let compat: AeadTransform | undefined;
      const getCompat = () => {
        if (!compat) {
          jsCompat ??= createAesGcmComponent(createBlockCipher);
          compat = jsCompat.create(params);
        }
        return compat;
      };

      return {
        seal(sealParams) {
          const tagLength = resolveTagLength(sealParams.tagLength);
          return canUseNodeNativeTagLength(tagLength)
            ? native.seal(sealParams)
            : getCompat().seal(sealParams);
        },

        open(openParams) {
          const tagLength = resolveOpenTagLength(openParams);
          return canUseNodeNativeTagLength(tagLength)
            ? native.open(openParams)
            : getCompat().open(openParams);
        },
      };
    },
  };
}

function createNodeNativeTransform({ key }: AeadCreateParams): AeadTransform {
  assertBytes(key, 'AES-GCM key');
  const algorithm = resolveAlgorithm(key);

  return {
    seal({ plaintext, nonce, aad, tagLength }: AeadSealParams): Uint8Array {
      assertBytes(plaintext, 'AES-GCM plaintext');
      const resolvedNonce = requireNonce(nonce);
      const resolvedAad = resolveAad(aad);
      const resolvedTagLength = resolveTagLength(tagLength);

      const cipher = createCipheriv(algorithm, key, resolvedNonce, {
        authTagLength: resolvedTagLength,
      });
      if (resolvedAad.length !== 0) {
        cipher.setAAD(resolvedAad);
      }
      const ciphertext = concatBytes(cipher.update(plaintext), cipher.final());
      return concatBytes(ciphertext, cipher.getAuthTag());
    },

    open({ ciphertext, nonce, aad, tag, tagLength }: AeadOpenParams): Uint8Array {
      assertBytes(ciphertext, 'AES-GCM ciphertext');
      const resolvedNonce = requireNonce(nonce);
      const resolvedAad = resolveAad(aad);
      const detachedTag = resolveOptionalTag(tag);
      const resolvedTagLength = detachedTag ? detachedTag.length : resolveTagLength(tagLength);

      let actualCiphertext = ciphertext;
      let actualTag = detachedTag;
      if (!actualTag) {
        if (ciphertext.length < resolvedTagLength) {
          throw new Error('AES-GCM ciphertext must include an authentication tag.');
        }
        actualCiphertext = ciphertext.subarray(0, ciphertext.length - resolvedTagLength);
        actualTag = ciphertext.subarray(ciphertext.length - resolvedTagLength);
      }

      try {
        const decipher = createDecipheriv(algorithm, key, resolvedNonce, {
          authTagLength: resolvedTagLength,
        });
        if (resolvedAad.length !== 0) {
          decipher.setAAD(resolvedAad);
        }
        decipher.setAuthTag(actualTag);
        return concatBytes(decipher.update(actualCiphertext), decipher.final());
      } catch {
        throw new Error('AES-GCM authentication failed.');
      }
    },
  };
}

function canUseNodeNativeTagLength(tagLength: number): boolean {
  return NODE_NATIVE_TAG_LENGTHS.has(tagLength);
}

function resolveOpenTagLength(params: AeadOpenParams): number {
  if (params.tag !== undefined) {
    assertBytes(params.tag, 'AES-GCM tag');
    return params.tag.length;
  }
  return resolveTagLength(params.tagLength);
}

function resolveAlgorithm(key: Uint8Array): string {
  if (key.length !== 16 && key.length !== 24 && key.length !== 32) {
    throw new Error('AES key must be 128, 192, or 256 bits.');
  }
  return `aes-${key.length * 8}-gcm`;
}

function requireNonce(nonce: Uint8Array | undefined): Uint8Array {
  if (nonce === undefined || nonce.length === 0) {
    throw new Error('AES-GCM requires a nonce.');
  }
  assertBytes(nonce, 'AES-GCM nonce');
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
