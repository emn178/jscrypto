import type { AeadComponent, AeadTransform } from './component.js';
import type { Registry } from './registry.js';

export interface CreateAeadOptions {
  algorithm: string;
  key: Uint8Array;
  [option: string]: unknown;
}

export interface AeadSealOperationOptions {
  nonce?: Uint8Array;
  aad?: Uint8Array;
  tagLength?: number;
  [option: string]: unknown;
}

export interface AeadOpenOperationOptions {
  nonce?: Uint8Array;
  aad?: Uint8Array;
  tag?: Uint8Array;
  tagLength?: number;
  [option: string]: unknown;
}

export interface AeadFacade {
  seal(plaintext: Uint8Array, options?: AeadSealOperationOptions): Uint8Array;
  open(ciphertext: Uint8Array, options?: AeadOpenOperationOptions): Uint8Array;
}

/**
 * AEAD operation options only reserve facade identity keys.
 * Unlike createCipher, cipher-pipeline keys such as `mode`, `padding`, `cipher`,
 * and `iv` are treated as unknown extras and ignored by core.
 */
const AEAD_RESERVED_OPERATION_OPTION_KEYS = ['algorithm', 'key'] as const;

function assertNoAeadReservedOperationOptions(
  options: Record<string, unknown> | undefined,
): void {
  if (!options) {
    return;
  }
  for (const key of AEAD_RESERVED_OPERATION_OPTION_KEYS) {
    if (Object.prototype.hasOwnProperty.call(options, key)) {
      throw new Error(`operation options must not override reserved key: ${key}`);
    }
  }
}

function splitCreateAeadOptions(options: CreateAeadOptions): {
  algorithm: string;
  key: Uint8Array;
  createOptions: Record<string, unknown>;
} {
  const { algorithm, key, ...createOptions } = options;
  return { algorithm, key, createOptions };
}

function mergeAeadOptions(
  createOptions: Record<string, unknown>,
  operation?: Record<string, unknown>,
): Record<string, unknown> {
  if (!operation) {
    return createOptions;
  }
  assertNoAeadReservedOperationOptions(operation);
  return { ...createOptions, ...operation };
}

export function createAead(registry: Registry, options: CreateAeadOptions): AeadFacade {
  const { algorithm, key, createOptions } = splitCreateAeadOptions(options);
  const component = registry.get<'aead', AeadComponent>('aead', algorithm);
  // create() once: AeadTransform must be reusable/stateless across seal/open calls.
  const transform: AeadTransform = component.create({ key, options: createOptions });

  return {
    seal(plaintext, operationOptions) {
      const merged = mergeAeadOptions(createOptions, operationOptions);
      return transform.seal({
        plaintext,
        nonce: merged.nonce as Uint8Array | undefined,
        aad: merged.aad as Uint8Array | undefined,
        tagLength: merged.tagLength as number | undefined,
        options: merged,
      });
    },

    open(ciphertext, operationOptions) {
      const merged = mergeAeadOptions(createOptions, operationOptions);
      return transform.open({
        ciphertext,
        nonce: merged.nonce as Uint8Array | undefined,
        aad: merged.aad as Uint8Array | undefined,
        tag: merged.tag as Uint8Array | undefined,
        tagLength: merged.tagLength as number | undefined,
        options: merged,
      });
    },
  };
}
