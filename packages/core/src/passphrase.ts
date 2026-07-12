import type { CipherComponent, FormatComponent, KdfComponent, Transform } from './component.js';
import type { Registry } from './registry.js';
import type { CreateTransformOptions } from './transform.js';
import { concatBytes } from './bytes.js';

export interface CreatePassphraseCipherOptions {
  cipher: string;
  mode?: string;
  padding?: string;
  passphrase: Uint8Array | string;
  kdf: string | KdfOptions;
  format?: string | FormatOptions;
  salt?: Uint8Array;
  saltSize?: number;
  keySize?: number;
  ivSize?: number;
  [option: string]: unknown;
}

export interface KdfOptions {
  name: string;
  [option: string]: unknown;
}

export interface FormatOptions {
  name: string;
  [option: string]: unknown;
}

export interface PassphraseCipherFacade {
  encrypt(plaintext: Uint8Array): Uint8Array;
  decrypt(input: Uint8Array): Uint8Array;
  createEncryptor(): Transform;
  createDecryptor(): Transform;
}

export function createPassphraseCipher(
  registry: Registry,
  options: CreatePassphraseCipherOptions,
): PassphraseCipherFacade {
  return {
    encrypt(plaintext) {
      return concatBytes(this.createEncryptor().finalize(plaintext));
    },

    decrypt(input) {
      return concatBytes(this.createDecryptor().finalize(input));
    },

    createEncryptor() {
      return createPassphraseEncryptor(registry, options);
    },

    createDecryptor() {
      return createPassphraseDecryptor(registry, options);
    },
  };
}

function createPassphraseEncryptor(
  registry: Registry,
  options: CreatePassphraseCipherOptions,
): Transform {
  const format = resolveFormat(registry, options);
  const salt = options.salt ? options.salt.slice() : randomBytes(options.saltSize ?? 8);
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

function createPassphraseDecryptor(
  registry: Registry,
  options: CreatePassphraseCipherOptions,
): Transform {
  const format = resolveFormat(registry, options);

  if (!format) {
    const { key, iv } = deriveKeyIv(registry, options, new Uint8Array(0));
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
  options: CreatePassphraseCipherOptions,
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
  options: CreatePassphraseCipherOptions,
  salt: Uint8Array,
): { key: Uint8Array; iv?: Uint8Array } {
  const keySize = resolveKeySize(registry, options);
  const ivSize = resolveIvSize(registry, options);
  const derived = deriveSync(registry, options, salt, keySize + ivSize);
  return {
    key: derived.slice(0, keySize),
    iv: ivSize === 0 ? undefined : derived.slice(keySize, keySize + ivSize),
  };
}

function deriveSync(
  registry: Registry,
  options: CreatePassphraseCipherOptions,
  salt: Uint8Array,
  length: number,
): Uint8Array {
  const kdfOptions = normalizeNamedOptions(options.kdf);
  const kdf = registry.get<'kdf', KdfComponent>('kdf', kdfOptions.name);
  const result = kdf.derive({
    ...withoutName(kdfOptions),
    passphrase: options.passphrase,
    salt,
    length,
  });
  if (result instanceof Promise) {
    throw new Error(`KDF ${kdfOptions.name} is asynchronous; use an async passphrase cipher API.`);
  }
  return result;
}

function toTransformOptions(
  options: CreatePassphraseCipherOptions,
  key: Uint8Array,
  iv: Uint8Array | undefined,
): CreateTransformOptions {
  const {
    passphrase,
    kdf,
    format,
    salt,
    saltSize,
    keySize,
    ivSize,
    ...transformOptions
  } = options;

  return {
    ...transformOptions,
    key,
    ...(iv ? { iv } : {}),
  };
}

function resolveKeySize(registry: Registry, options: CreatePassphraseCipherOptions): number {
  if (options.keySize !== undefined) {
    assertPositiveInteger(options.keySize, 'keySize');
    return options.keySize;
  }

  const cipher = registry.get<'cipher', CipherComponent>('cipher', options.cipher);
  if (!cipher.keySizes || cipher.keySizes.length === 0) {
    throw new Error(`${options.cipher} passphrase cipher requires keySize.`);
  }
  return Math.max(...cipher.keySizes);
}

function resolveIvSize(registry: Registry, options: CreatePassphraseCipherOptions): number {
  if (options.ivSize !== undefined) {
    assertNonNegativeInteger(options.ivSize, 'ivSize');
    return options.ivSize;
  }

  const cipher = registry.get<'cipher', CipherComponent>('cipher', options.cipher);
  return cipher.type === 'block' ? cipher.blockSize : 0;
}

function resolveFormat(
  registry: Registry,
  options: CreatePassphraseCipherOptions,
): FormatComponent | undefined {
  if (!options.format) {
    return undefined;
  }
  return registry.get<'format', FormatComponent>('format', normalizeNamedOptions(options.format).name);
}

function isStreamingOpenSslFormat(format: FormatComponent): boolean {
  return format.name === 'OpenSSL';
}

function normalizeNamedOptions(options: string | { name: string }): { name: string; [option: string]: unknown } {
  return typeof options === 'string' ? { name: options } : options;
}

function withoutName(options: { name: string; [option: string]: unknown }): Record<string, unknown> {
  const { name, ...rest } = options;
  return rest;
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
