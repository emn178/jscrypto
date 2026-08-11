import type {
  BlockCipherComponent,
  CipherComponent,
  AeadComponent,
  FormatComponent,
  KdfComponent,
  ModeComponent,
  Transform,
} from './component.js';
import type {
  AeadFacade,
  AeadOpenOperationOptions,
  AeadSealOperationOptions,
  CreateAeadOptions,
} from './aead.js';
import type { DerivedKeyCipherOperationOptions } from './operation-options.js';
import { assertNoReservedOperationOptions } from './operation-options.js';
import type { Registry } from './registry.js';
import type { CreateTransformOptions } from './transform.js';
import { concatBytes } from './bytes.js';

export interface DeriveOptions {
  name: string;
  length: number;
  input?: Uint8Array | string;
  [key: string]: unknown;
}

export interface KdfOptions {
  name: string;
  [option: string]: unknown;
}

export interface FormatOptions {
  name: string;
  [option: string]: unknown;
}

export interface CreateDerivedKeyCipherOptions {
  cipher: string;
  mode?: string;
  padding?: string;
  format?: string | (FormatOptions & { saltSize?: number });
  kdf: Omit<DeriveOptions, 'length'> & { length?: number };
  keySize?: number;
  [key: string]: unknown;
}

export interface CreateDerivedKeyAeadOptions {
  algorithm: string;
  format?: string | (FormatOptions & { saltSize?: number });
  kdf: Omit<DeriveOptions, 'length'> & { length?: number };
  keySize?: number;
  [key: string]: unknown;
}

export interface DerivedKeyCipherFacade {
  encrypt(plaintext: Uint8Array, options?: DerivedKeyCipherOperationOptions): Uint8Array;
  decrypt(input: Uint8Array, options?: DerivedKeyCipherOperationOptions): Uint8Array;
  createEncryptor(options?: DerivedKeyCipherOperationOptions): Transform;
  createDecryptor(options?: DerivedKeyCipherOperationOptions): Transform;
}

export interface DerivedKeyAeadSealOperationOptions extends AeadSealOperationOptions {
  salt?: Uint8Array | string | null;
}

export interface DerivedKeyAeadOpenOperationOptions extends AeadOpenOperationOptions {
  salt?: Uint8Array | string | null;
}

export interface DerivedKeyAeadFacade {
  seal(plaintext: Uint8Array, options?: DerivedKeyAeadSealOperationOptions): Uint8Array;
  open(ciphertext: Uint8Array, options?: DerivedKeyAeadOpenOperationOptions): Uint8Array;
  createSealer(options?: DerivedKeyAeadSealOperationOptions): Transform;
  createOpener(options?: DerivedKeyAeadOpenOperationOptions): Transform;
}

export function derive(
  registry: Registry,
  options: DeriveOptions,
): Uint8Array {
  const { name, ...params } = options;
  const kdf = registry.get<'kdf', KdfComponent>('kdf', name);
  const result = kdf.derive(params, {
    getHash: registry.getHash.bind(registry),
  });
  if (!(result instanceof Uint8Array)) {
    throw new TypeError(`KDF ${name} must return a Uint8Array.`);
  }
  return result;
}

export function createDerivedKeyCipher(
  registry: Registry,
  options: CreateDerivedKeyCipherOptions,
): DerivedKeyCipherFacade {
  assertDerivedKeyOptions(options);

  return {
    encrypt(plaintext, operationOptions) {
      return concatBytes(this.createEncryptor(operationOptions).finalize(plaintext));
    },

    decrypt(input, operationOptions) {
      return concatBytes(this.createDecryptor(operationOptions).finalize(input));
    },

    createEncryptor(operationOptions) {
      return createDerivedKeyEncryptor(registry, options, operationOptions);
    },

    createDecryptor(operationOptions) {
      return createDerivedKeyDecryptor(registry, options, operationOptions);
    },
  };
}

export function createDerivedKeyAead(
  registry: Registry,
  options: CreateDerivedKeyAeadOptions,
): DerivedKeyAeadFacade {
  assertDerivedKeyOptions(options, 'createDerivedKeyAead');

  function createSealer(operationOptions?: DerivedKeyAeadSealOperationOptions): Transform {
    return createDerivedKeyAeadSealer(registry, options, operationOptions);
  }

  function createOpener(operationOptions?: DerivedKeyAeadOpenOperationOptions): Transform {
    return createDerivedKeyAeadOpener(registry, options, operationOptions);
  }

  return {
    seal(plaintext, operationOptions) {
      return concatBytes(createSealer(operationOptions).finalize(plaintext));
    },

    open(ciphertext, operationOptions) {
      return concatBytes(createOpener(operationOptions).finalize(ciphertext));
    },

    createSealer,
    createOpener,
  };
}

function createDerivedKeyEncryptor(
  registry: Registry,
  options: CreateDerivedKeyCipherOptions,
  operationOptions?: DerivedKeyCipherOperationOptions,
): Transform {
  const formatOptions = resolveFormatOptions(options.format);
  const format = resolveFormat(registry, formatOptions);
  const salt = resolveSalt(options, operationOptions);
  const { key, iv } = deriveKeyIv(registry, options, salt);
  const encryptor = registry.createCipher(toTransformOptions(options, key, iv, operationOptions)).createEncryptor();

  if (!format) {
    return encryptor;
  }

  if (!isStreamingOpenSslFormat(format)) {
    return createBufferedFormatEncryptor(format, salt, encryptor);
  }

  let emittedHeader = false;
  const emitHeader = (): Uint8Array => {
    if (emittedHeader) {
      return new Uint8Array(0);
    }
    emittedHeader = true;
    return format.stringify({ ciphertext: new Uint8Array(0), salt });
  };

  return {
    process(input) {
      return concatBytes(emitHeader(), encryptor.process(input));
    },

    finalize(input = new Uint8Array(0)) {
      return concatBytes(emitHeader(), encryptor.finalize(input));
    },
  };
}

function createDerivedKeyDecryptor(
  registry: Registry,
  options: CreateDerivedKeyCipherOptions,
  operationOptions?: DerivedKeyCipherOperationOptions,
): Transform {
  const formatOptions = resolveFormatOptions(options.format);
  const format = resolveFormat(registry, formatOptions);

  if (!format) {
    const salt = resolveSalt(options, operationOptions);
    const { key, iv } = deriveKeyIv(registry, options, salt);
    return registry.createCipher(toTransformOptions(options, key, iv, operationOptions)).createDecryptor();
  }

  if (!isStreamingOpenSslFormat(format)) {
    return createBufferedFormatDecryptor(registry, options, format, operationOptions);
  }

  let header = new Uint8Array(0);
  let decryptor: Transform | undefined;

  const initDecryptor = (input: Uint8Array): Uint8Array => {
    if (decryptor) {
      return input;
    }

    header = new Uint8Array(concatBytes(header, input));
    if (header.length < 16) {
      return new Uint8Array(0);
    }

    const parsed = format.parse(header.slice(0, 16));
    const hasSalt = parsed.salt !== undefined;
    const salt = hasSalt ? parsed.salt! : resolveOpenSslDecryptSaltWithoutHeader(options, operationOptions);
    const ciphertext = hasSalt ? concatBytes(parsed.ciphertext, header.slice(16)) : header;
    const { key, iv } = deriveKeyIv(registry, options, salt);
    decryptor = registry.createCipher(toTransformOptions(options, key, iv, operationOptions)).createDecryptor();
    header = new Uint8Array(0);
    return ciphertext;
  };

  return {
    process(input) {
      const ciphertext = initDecryptor(input);
      return decryptor ? decryptor.process(ciphertext) : new Uint8Array(0);
    },

    finalize(input = new Uint8Array(0)) {
      const ciphertext = initDecryptor(input);
      if (!decryptor) {
        const salt = resolveOpenSslDecryptSaltWithoutHeader(options, operationOptions);
        const { key, iv } = deriveKeyIv(registry, options, salt);
        decryptor = registry.createCipher(toTransformOptions(options, key, iv, operationOptions)).createDecryptor();
        const buffered = header;
        header = new Uint8Array(0);
        return decryptor.finalize(buffered);
      }
      return decryptor.finalize(ciphertext);
    },
  };
}

function createDerivedKeyAeadSealer(
  registry: Registry,
  options: CreateDerivedKeyAeadOptions,
  operationOptions?: DerivedKeyAeadSealOperationOptions,
): Transform {
  const formatOptions = resolveFormatOptions(options.format);
  const format = resolveFormat(registry, formatOptions);
  const salt = resolveSalt(options, operationOptions);
  const key = deriveAeadKey(registry, options, salt);
  const sealer = registry.createAead(toAeadOptions(options, key)).createSealer(toAeadOperationOptions(operationOptions));

  if (!format) {
    return sealer;
  }

  if (!isStreamingOpenSslFormat(format)) {
    return createBufferedAeadFormatSealer(format, salt, sealer);
  }

  let emittedHeader = false;
  const emitHeader = (): Uint8Array => {
    if (emittedHeader) {
      return new Uint8Array(0);
    }
    emittedHeader = true;
    return format.stringify({ ciphertext: new Uint8Array(0), salt });
  };

  return {
    process(input) {
      return concatBytes(emitHeader(), sealer.process(input));
    },

    finalize(input = new Uint8Array(0)) {
      return concatBytes(emitHeader(), sealer.finalize(input));
    },
  };
}

function createDerivedKeyAeadOpener(
  registry: Registry,
  options: CreateDerivedKeyAeadOptions,
  operationOptions?: DerivedKeyAeadOpenOperationOptions,
): Transform {
  const formatOptions = resolveFormatOptions(options.format);
  const format = resolveFormat(registry, formatOptions);

  if (!format) {
    const salt = resolveSalt(options, operationOptions);
    const key = deriveAeadKey(registry, options, salt);
    return registry.createAead(toAeadOptions(options, key)).createOpener(toAeadOperationOptions(operationOptions));
  }

  if (!isStreamingOpenSslFormat(format)) {
    return createBufferedAeadFormatOpener(registry, options, format, operationOptions);
  }

  let header = new Uint8Array(0);
  let opener: Transform | undefined;

  const initOpener = (input: Uint8Array): Uint8Array => {
    if (opener) {
      return input;
    }

    header = new Uint8Array(concatBytes(header, input));
    if (header.length < 16) {
      return new Uint8Array(0);
    }

    const parsed = format.parse(header.slice(0, 16));
    const hasSalt = parsed.salt !== undefined;
    const salt = hasSalt ? parsed.salt! : resolveOpenSslDecryptSaltWithoutHeader(options, operationOptions);
    const ciphertext = hasSalt ? concatBytes(parsed.ciphertext, header.slice(16)) : header;
    const key = deriveAeadKey(registry, options, salt);
    opener = registry.createAead(toAeadOptions(options, key)).createOpener(toAeadOperationOptions(operationOptions));
    header = new Uint8Array(0);
    return ciphertext;
  };

  return {
    process(input) {
      const ciphertext = initOpener(input);
      return opener ? opener.process(ciphertext) : new Uint8Array(0);
    },

    finalize(input = new Uint8Array(0)) {
      const ciphertext = initOpener(input);
      if (!opener) {
        const salt = resolveOpenSslDecryptSaltWithoutHeader(options, operationOptions);
        const key = deriveAeadKey(registry, options, salt);
        opener = registry.createAead(toAeadOptions(options, key)).createOpener(toAeadOperationOptions(operationOptions));
        const buffered = header;
        header = new Uint8Array(0);
        return opener.finalize(buffered);
      }
      return opener.finalize(ciphertext);
    },
  };
}

function createBufferedFormatEncryptor(
  format: FormatComponent,
  salt: Uint8Array | undefined,
  encryptor: Transform,
): Transform {
  const chunks: Uint8Array[] = [];

  return {
    process(input) {
      const output = encryptor.process(input);
      if (output.length !== 0) {
        chunks.push(output);
      }
      return new Uint8Array(0);
    },

    finalize(input = new Uint8Array(0)) {
      const output = encryptor.finalize(input);
      if (output.length !== 0) {
        chunks.push(output);
      }
      return format.stringify({ ciphertext: concatBytes(...chunks), salt });
    },
  };
}

function createBufferedAeadFormatSealer(
  format: FormatComponent,
  salt: Uint8Array | undefined,
  sealer: Transform,
): Transform {
  const chunks: Uint8Array[] = [];

  return {
    process(input) {
      const output = sealer.process(input);
      if (output.length !== 0) {
        chunks.push(output);
      }
      return new Uint8Array(0);
    },

    finalize(input = new Uint8Array(0)) {
      const output = sealer.finalize(input);
      if (output.length !== 0) {
        chunks.push(output);
      }
      return format.stringify({ ciphertext: concatBytes(...chunks), salt });
    },
  };
}

function createBufferedAeadFormatOpener(
  registry: Registry,
  options: CreateDerivedKeyAeadOptions,
  format: FormatComponent,
  operationOptions?: DerivedKeyAeadOpenOperationOptions,
): Transform {
  const chunks: Uint8Array[] = [];

  return {
    process(input) {
      if (input.length !== 0) {
        chunks.push(input);
      }
      return new Uint8Array(0);
    },

    finalize(input = new Uint8Array(0)) {
      if (input.length !== 0) {
        chunks.push(input);
      }
      const parsed = format.parse(concatBytes(...chunks));
      const salt = parsed.salt ?? resolveSalt(options, operationOptions);
      const key = deriveAeadKey(registry, options, salt);
      return registry.createAead(toAeadOptions(options, key)).open(parsed.ciphertext, toAeadOperationOptions(operationOptions));
    },
  };
}

function createBufferedFormatDecryptor(
  registry: Registry,
  options: CreateDerivedKeyCipherOptions,
  format: FormatComponent,
  operationOptions?: DerivedKeyCipherOperationOptions,
): Transform {
  const chunks: Uint8Array[] = [];

  return {
    process(input) {
      if (input.length !== 0) {
        chunks.push(input);
      }
      return new Uint8Array(0);
    },

    finalize(input = new Uint8Array(0)) {
      if (input.length !== 0) {
        chunks.push(input);
      }
      const parsed = format.parse(concatBytes(...chunks));
      const salt = parsed.salt ?? resolveSalt(options, operationOptions);
      const { key, iv } = deriveKeyIv(registry, options, salt);
      return registry.createCipher(toTransformOptions(options, key, iv, operationOptions)).decrypt(parsed.ciphertext);
    },
  };
}

function deriveAeadKey(
  registry: Registry,
  options: CreateDerivedKeyAeadOptions,
  salt: Uint8Array | undefined,
): Uint8Array {
  const keySize = resolveAeadKeySize(registry, options);
  if (options.kdf.length !== undefined && options.kdf.length !== keySize) {
    throw new Error(`kdf.length (${options.kdf.length}) does not match derived material length (${keySize}).`);
  }
  return deriveForKey(registry, options, salt, keySize);
}

function deriveKeyIv(
  registry: Registry,
  options: CreateDerivedKeyCipherOptions,
  salt: Uint8Array | undefined,
): { key: Uint8Array; iv?: Uint8Array } {
  const keySize = resolveKeySize(registry, options);
  const ivSize = resolveIvSize(registry, options);
  const length = keySize + ivSize;
  if (options.kdf.length !== undefined && options.kdf.length !== length) {
    throw new Error(`kdf.length (${options.kdf.length}) does not match derived material length (${length}).`);
  }
  const derived = deriveForKey(registry, options, salt, length);
  return {
    key: derived.slice(0, keySize),
    iv: ivSize === 0 ? undefined : derived.slice(keySize, keySize + ivSize),
  };
}

function deriveForKey(
  registry: Registry,
  options: CreateDerivedKeyCipherOptions | CreateDerivedKeyAeadOptions,
  salt: Uint8Array | undefined,
  length: number,
): Uint8Array {
  const name = options.kdf.name;
  const { name: _name, length: _ignoredLength, salt: _ignoredSalt, ...kdfParams } = options.kdf;
  return derive(registry, {
    ...kdfParams,
    name,
    ...(salt !== undefined ? { salt } : {}),
    length,
  } as DeriveOptions);
}

function toAeadOptions(
  options: CreateDerivedKeyAeadOptions,
  key: Uint8Array,
): CreateAeadOptions {
  const {
    kdf,
    format,
    keySize,
    salt,
    saltSize,
    ...aeadOptions
  } = options;
  return {
    ...aeadOptions,
    key,
  } as CreateAeadOptions;
}

function toTransformOptions(
  options: CreateDerivedKeyCipherOptions,
  key: Uint8Array,
  iv: Uint8Array | undefined,
  operationOptions?: DerivedKeyCipherOperationOptions,
): CreateTransformOptions {
  const {
    kdf,
    format,
    keySize,
    ivSize,
    salt,
    saltSize,
    ...transformOptions
  } = options;
  const cipherOperation = operationOptions ? stripSalt(operationOptions) : undefined;
  if (cipherOperation) {
    assertNoReservedOperationOptions(cipherOperation);
  }
  return {
    ...transformOptions,
    ...cipherOperation,
    key,
    ...(iv ? { iv } : {}),
  };
}

function stripSalt<T extends { salt?: unknown }>(operationOptions: T | undefined): Omit<T, 'salt'> | undefined {
  if (!operationOptions) {
    return undefined;
  }
  const { salt: _salt, ...cipherOperation } = operationOptions;
  return cipherOperation;
}

type CipherOperationWithoutSalt = Omit<DerivedKeyCipherOperationOptions, 'salt'>;

function toAeadOperationOptions<T extends { salt?: unknown }>(operationOptions: T | undefined): Omit<T, 'salt'> | undefined {
  const aeadOperation = stripSalt(operationOptions);
  assertNoReservedOperationOptions(aeadOperation);
  return aeadOperation;
}

function resolveSalt(
  options: CreateDerivedKeyCipherOptions | CreateDerivedKeyAeadOptions,
  operationOptions: { salt?: Uint8Array | string | null } | undefined,
): Uint8Array | undefined {
  const operationSalt = resolveOperationSalt(operationOptions);
  if (operationSalt !== undefined) {
    return operationSalt;
  }

  const creationSalt = resolveCreationSalt(options);
  if (creationSalt !== undefined) {
    return creationSalt;
  }

  return undefined;
}

function resolveOpenSslDecryptSaltWithoutHeader(
  options: CreateDerivedKeyCipherOptions | CreateDerivedKeyAeadOptions,
  operationOptions: { salt?: Uint8Array | string | null } | undefined,
): Uint8Array | undefined {
  const operationSalt = resolveOperationSalt(operationOptions);
  if (operationSalt !== undefined) {
    return operationSalt;
  }

  const creationSalt = resolveCreationSalt(options);
  if (creationSalt !== undefined) {
    return creationSalt;
  }

  return new Uint8Array(0);
}

function resolveOperationSalt(
  operationOptions: { salt?: Uint8Array | string | null } | undefined,
): Uint8Array | undefined {
  if (!operationOptions || !Object.prototype.hasOwnProperty.call(operationOptions, 'salt')) {
    return undefined;
  }
  return normalizeSalt(operationOptions.salt, 'salt');
}

function resolveCreationSalt(options: CreateDerivedKeyCipherOptions | CreateDerivedKeyAeadOptions): Uint8Array | undefined {
  if (!Object.prototype.hasOwnProperty.call(options.kdf, 'salt')) {
    return undefined;
  }
  return normalizeSalt(options.kdf.salt as Uint8Array | string | null | undefined, 'kdf.salt');
}

function normalizeSalt(
  salt: Uint8Array | string | null | undefined,
  label = 'salt',
): Uint8Array {
  if (salt === undefined || salt === null) {
    return new Uint8Array(0);
  }
  if (typeof salt === 'string') {
    return new TextEncoder().encode(salt);
  }
  if (salt instanceof Uint8Array) {
    return salt.slice();
  }
  throw new TypeError(`${label} must be a Uint8Array or string.`);
}

function assertDerivedKeyOptions(
  options: CreateDerivedKeyCipherOptions | CreateDerivedKeyAeadOptions,
  label = 'createDerivedKeyCipher',
): void {
  if (!options.kdf || typeof options.kdf !== 'object' || Array.isArray(options.kdf)) {
    throw new TypeError(`${label} requires kdf to be an object with name and input.`);
  }
  if (typeof options.kdf.name !== 'string' || options.kdf.name.length === 0) {
    throw new TypeError(`${label} requires kdf.name.`);
  }
  if (options.kdf.input === undefined || options.kdf.input === null) {
    throw new TypeError(`KDF ${options.kdf.name} requires input.`);
  }
}

function resolveAeadKeySize(registry: Registry, options: CreateDerivedKeyAeadOptions): number {
  if (options.keySize !== undefined) {
    assertPositiveInteger(options.keySize, 'keySize');
    return options.keySize;
  }

  const aead = registry.get<'aead', AeadComponent>('aead', options.algorithm);
  if (!aead.keySizes || aead.keySizes.length === 0) {
    throw new Error(`${options.algorithm} derived-key AEAD requires keySize.`);
  }
  return Math.max(...aead.keySizes);
}

function resolveKeySize(registry: Registry, options: CreateDerivedKeyCipherOptions): number {
  if (options.keySize !== undefined) {
    assertPositiveInteger(options.keySize, 'keySize');
    return options.keySize;
  }

  const cipher = registry.get<'cipher', CipherComponent>('cipher', options.cipher);
  if (!cipher.keySizes || cipher.keySizes.length === 0) {
    throw new Error(`${options.cipher} derived-key cipher requires keySize.`);
  }
  return Math.max(...cipher.keySizes);
}

function resolveIvSize(registry: Registry, options: CreateDerivedKeyCipherOptions): number {
  const cipher = registry.get<'cipher', CipherComponent>('cipher', options.cipher);
  if (cipher.type !== 'block') {
    return 0;
  }
  if (!options.mode) {
    return 0;
  }

  const mode = registry.get<'mode', ModeComponent>('mode', options.mode);
  return mode.getIvSize?.(cipher as BlockCipherComponent) ?? 0;
}

function resolveFormatOptions(
  format: CreateDerivedKeyCipherOptions['format'],
): (FormatOptions & { saltSize?: number }) | undefined {
  if (!format) {
    return undefined;
  }
  return typeof format === 'string' ? { name: format } : format;
}

function resolveFormat(
  registry: Registry,
  formatOptions: (FormatOptions & { saltSize?: number }) | undefined,
): FormatComponent | undefined {
  if (!formatOptions) {
    return undefined;
  }
  return registry.get<'format', FormatComponent>('format', formatOptions.name);
}

function isStreamingOpenSslFormat(format: FormatComponent): boolean {
  return format.name === 'OpenSSL';
}

function assertPositiveInteger(value: number, label: string): void {
  if (!Number.isInteger(value) || value <= 0) {
    throw new RangeError(`${label} must be a positive integer.`);
  }
}

declare const TextEncoder: {
  new(): { encode(input: string): Uint8Array };
};
