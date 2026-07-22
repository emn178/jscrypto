import type { CipherComponent, FormatComponent, KdfComponent, Transform } from './component.js';
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
  ivSize?: number;
  [key: string]: unknown;
}

export interface DerivedKeyCipherFacade {
  encrypt(plaintext: Uint8Array): Uint8Array;
  decrypt(input: Uint8Array): Uint8Array;
  createEncryptor(): Transform;
  createDecryptor(): Transform;
}

export interface DerivedKeyCipherRuntimeOptions {
  implicitRandomSalt?: boolean;
  defaultSaltSize?: number;
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
  runtime: DerivedKeyCipherRuntimeOptions = {},
): DerivedKeyCipherFacade {
  assertDerivedKeyOptions(options);

  return {
    encrypt(plaintext) {
      return concatBytes(this.createEncryptor().finalize(plaintext));
    },

    decrypt(input) {
      return concatBytes(this.createDecryptor().finalize(input));
    },

    createEncryptor() {
      return createDerivedKeyEncryptor(registry, options, runtime);
    },

    createDecryptor() {
      return createDerivedKeyDecryptor(registry, options, runtime);
    },
  };
}

function createDerivedKeyEncryptor(
  registry: Registry,
  options: CreateDerivedKeyCipherOptions,
  runtime: DerivedKeyCipherRuntimeOptions,
): Transform {
  const formatOptions = resolveFormatOptions(options.format);
  const format = resolveFormat(registry, formatOptions);
  const salt = resolveEncryptSalt(options, formatOptions, format, runtime);
  const { key, iv } = deriveKeyIv(registry, options, salt);
  const encryptor = registry.createCipher(toTransformOptions(options, key, iv)).createEncryptor();

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
  runtime: DerivedKeyCipherRuntimeOptions,
): Transform {
  const formatOptions = resolveFormatOptions(options.format);
  const format = resolveFormat(registry, formatOptions);

  if (!format) {
    const explicit = resolveExplicitSalt(options);
    if (explicit === undefined && !runtime.implicitRandomSalt) {
      throw new Error(`KDF ${options.kdf.name} requires salt; provide kdf.salt or a salt-generating format.`);
    }
    const { key, iv } = deriveKeyIv(registry, options, explicit ?? new Uint8Array(0));
    return registry.createCipher(toTransformOptions(options, key, iv)).createDecryptor();
  }

  if (!isStreamingOpenSslFormat(format)) {
    return createBufferedFormatDecryptor(registry, options, format);
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
    const salt = parsed.salt ?? new Uint8Array(0);
    const ciphertext = hasSalt ? concatBytes(parsed.ciphertext, header.slice(16)) : header;
    const { key, iv } = deriveKeyIv(registry, options, salt);
    decryptor = registry.createCipher(toTransformOptions(options, key, iv)).createDecryptor();
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
        const { key, iv } = deriveKeyIv(registry, options, new Uint8Array(0));
        decryptor = registry.createCipher(toTransformOptions(options, key, iv)).createDecryptor();
        const buffered = header;
        header = new Uint8Array(0);
        return decryptor.finalize(buffered);
      }
      return decryptor.finalize(ciphertext);
    },
  };
}

function createBufferedFormatEncryptor(
  format: FormatComponent,
  salt: Uint8Array,
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

function createBufferedFormatDecryptor(
  registry: Registry,
  options: CreateDerivedKeyCipherOptions,
  format: FormatComponent,
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
      const { key, iv } = deriveKeyIv(registry, options, parsed.salt ?? new Uint8Array(0));
      return registry.createCipher(toTransformOptions(options, key, iv)).decrypt(parsed.ciphertext);
    },
  };
}

function deriveKeyIv(
  registry: Registry,
  options: CreateDerivedKeyCipherOptions,
  salt: Uint8Array,
): { key: Uint8Array; iv?: Uint8Array } {
  const keySize = resolveKeySize(registry, options);
  const ivSize = resolveIvSize(registry, options);
  const length = keySize + ivSize;
  if (options.kdf.length !== undefined && options.kdf.length !== length) {
    throw new Error(`kdf.length (${options.kdf.length}) does not match keySize + ivSize (${length}).`);
  }
  const derived = deriveForCipher(registry, options, salt, length);
  return {
    key: derived.slice(0, keySize),
    iv: ivSize === 0 ? undefined : derived.slice(keySize, keySize + ivSize),
  };
}

function deriveForCipher(
  registry: Registry,
  options: CreateDerivedKeyCipherOptions,
  salt: Uint8Array,
  length: number,
): Uint8Array {
  const name = options.kdf.name;
  const { name: _name, length: _ignoredLength, ...kdfParams } = options.kdf;
  return derive(registry, {
    ...kdfParams,
    name,
    salt,
    length,
  } as DeriveOptions);
}

function toTransformOptions(
  options: CreateDerivedKeyCipherOptions,
  key: Uint8Array,
  iv: Uint8Array | undefined,
): CreateTransformOptions {
  const {
    kdf,
    format,
    keySize,
    ivSize,
    passphrase,
    salt,
    saltSize,
    ...transformOptions
  } = options;

  return {
    ...transformOptions,
    key,
    ...(iv ? { iv } : {}),
  };
}

function resolveEncryptSalt(
  options: CreateDerivedKeyCipherOptions,
  formatOptions: (FormatOptions & { saltSize?: number }) | undefined,
  format: FormatComponent | undefined,
  runtime: DerivedKeyCipherRuntimeOptions,
): Uint8Array {
  const explicit = resolveExplicitSalt(options);
  if (explicit !== undefined) {
    return explicit;
  }

  if (format) {
    if (runtime.implicitRandomSalt || isStreamingOpenSslFormat(format)) {
      return randomBytes(formatOptions!.saltSize ?? 8);
    }
  } else if (runtime.implicitRandomSalt) {
    return randomBytes(runtime.defaultSaltSize ?? 8);
  }

  throw new Error(`KDF ${options.kdf.name} requires salt; provide kdf.salt or a salt-generating format.`);
}

function resolveExplicitSalt(options: CreateDerivedKeyCipherOptions): Uint8Array | undefined {
  if (!Object.prototype.hasOwnProperty.call(options.kdf, 'salt')) {
    return undefined;
  }
  const salt = options.kdf.salt;
  if (salt === undefined || salt === null) {
    return new Uint8Array(0);
  }
  if (typeof salt === 'string') {
    return new TextEncoder().encode(salt);
  }
  if (salt instanceof Uint8Array) {
    return salt.slice();
  }
  throw new TypeError('kdf.salt must be a Uint8Array or string.');
}

function assertDerivedKeyOptions(options: CreateDerivedKeyCipherOptions): void {
  if (!options.kdf || typeof options.kdf !== 'object' || Array.isArray(options.kdf)) {
    throw new TypeError('createDerivedKeyCipher requires kdf to be an object with name and input.');
  }
  if (typeof options.kdf.name !== 'string' || options.kdf.name.length === 0) {
    throw new TypeError('createDerivedKeyCipher requires kdf.name.');
  }
  if (options.kdf.input === undefined || options.kdf.input === null) {
    throw new TypeError(`KDF ${options.kdf.name} requires input.`);
  }
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
  if (options.ivSize !== undefined) {
    assertNonNegativeInteger(options.ivSize, 'ivSize');
    return options.ivSize;
  }

  const cipher = registry.get<'cipher', CipherComponent>('cipher', options.cipher);
  return cipher.type === 'block' ? cipher.blockSize : 0;
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

function randomBytes(length: number): Uint8Array {
  assertNonNegativeInteger(length, 'saltSize');
  const bytes = new Uint8Array(length);
  if (bytes.length === 0) {
    return bytes;
  }

  const crypto = globalThis as typeof globalThis & {
    crypto?: {
      getRandomValues<T extends Uint8Array>(array: T): T;
    };
  };
  crypto.crypto?.getRandomValues(bytes);
  if (bytes.some((byte) => byte !== 0)) {
    return bytes;
  }

  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Math.floor(Math.random() * 256);
  }
  return bytes;
}

function assertPositiveInteger(value: number, label: string): void {
  if (!Number.isInteger(value) || value <= 0) {
    throw new RangeError(`${label} must be a positive integer.`);
  }
}

function assertNonNegativeInteger(value: number, label: string): void {
  if (!Number.isInteger(value) || value < 0) {
    throw new RangeError(`${label} must be a non-negative integer.`);
  }
}

declare const TextEncoder: {
  new(): { encode(input: string): Uint8Array };
};
