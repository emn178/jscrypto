import type {
  AeadComponent,
  AeadTransform,
  BlockCipher,
  BlockCipherComponent,
  CipherComponent,
  Transform,
} from './component.js';
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
  createSealer(options?: AeadSealOperationOptions): Transform;
  createOpener(options?: AeadOpenOperationOptions): Transform;
}

/**
 * AEAD operation options only reserve facade identity keys.
 * Unlike createCipher, cipher-pipeline keys such as `mode`, `padding`, `cipher`,
 * and `iv` are treated as unknown extras and ignored by core.
 */
const AEAD_RESERVED_OPERATION_OPTION_KEYS = ['algorithm', 'key'] as const;

function assertNoAeadReservedOperationOptions(
  options: Record<string, unknown>,
): void {
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
  // create() once: AeadTransform must be reusable and create fresh per-operation transforms.
  const transform: AeadTransform = component.create({ key, options: createOptions }, {
    createEncryptor(transformOptions) {
      return registry.createEncryptor(transformOptions);
    },
    createDecryptor(transformOptions) {
      return registry.createDecryptor(transformOptions);
    },
    createBlockCipher({ cipher, key: blockKey }): BlockCipher {
      const cipherComponent = registry.get<'cipher', CipherComponent>('cipher', cipher);
      if (cipherComponent.type !== 'block') {
        throw new Error(`Expected a block cipher component: ${cipher}`);
      }
      return (cipherComponent as BlockCipherComponent).create(blockKey);
    },
  });

  function createSealer(operationOptions?: AeadSealOperationOptions): Transform {
    const merged = mergeAeadOptions(createOptions, operationOptions);
    return transform.createSealer({
      nonce: merged.nonce as Uint8Array | undefined,
      aad: merged.aad as Uint8Array | undefined,
      tagLength: merged.tagLength as number | undefined,
      options: merged,
    });
  }

  function createOpener(operationOptions?: AeadOpenOperationOptions): Transform {
    const merged = mergeAeadOptions(createOptions, operationOptions);
    return transform.createOpener({
      nonce: merged.nonce as Uint8Array | undefined,
      aad: merged.aad as Uint8Array | undefined,
      tag: merged.tag as Uint8Array | undefined,
      tagLength: merged.tagLength as number | undefined,
      options: merged,
    });
  }

  return {
    seal(plaintext, operationOptions) {
      return createSealer(operationOptions).finalize(plaintext);
    },

    open(ciphertext, operationOptions) {
      return createOpener(operationOptions).finalize(ciphertext);
    },

    createSealer,
    createOpener,
  };
}
