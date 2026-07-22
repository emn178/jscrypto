import type {
  CreateDerivedKeyCipherOptions,
  DerivedKeyCipherFacade,
  FormatOptions,
  KdfOptions,
} from './derived-key.js';
import { createDerivedKeyCipher } from './derived-key.js';
import type { Registry } from './registry.js';

export type { FormatOptions, KdfOptions } from './derived-key.js';

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

/**
 * @deprecated Use createDerivedKeyCipher({ ..., kdf: { ..., input } }) instead.
 */
export type PassphraseCipherFacade = DerivedKeyCipherFacade;

/**
 * @deprecated Use createDerivedKeyCipher({ ..., kdf: { ..., input } }) instead.
 */
export function createPassphraseCipher(
  registry: Registry,
  options: CreatePassphraseCipherOptions,
): PassphraseCipherFacade {
  return createDerivedKeyCipher(
    registry,
    toDerivedKeyCipherOptions(options),
    {
      implicitRandomSalt: true,
      ...(options.saltSize !== undefined ? { defaultSaltSize: options.saltSize } : {}),
    },
  );
}

function toDerivedKeyCipherOptions(
  options: CreatePassphraseCipherOptions,
): CreateDerivedKeyCipherOptions {
  const kdfOptions: KdfOptions = typeof options.kdf === 'string'
    ? { name: options.kdf }
    : { ...options.kdf };

  const input = Object.prototype.hasOwnProperty.call(kdfOptions, 'input')
    ? kdfOptions.input as Uint8Array | string
    : options.passphrase;

  const salt = Object.prototype.hasOwnProperty.call(kdfOptions, 'salt')
    ? kdfOptions.salt as Uint8Array | string | undefined
    : options.salt;

  const {
    passphrase: _passphrase,
    kdf: _kdf,
    salt: _salt,
    saltSize,
    format,
    cipher,
    mode,
    padding,
    keySize,
    ivSize,
    ...rest
  } = options;

  return {
    ...rest,
    cipher,
    mode,
    padding,
    keySize,
    ivSize,
    format: normalizeFormatOptions(format, saltSize),
    kdf: {
      ...kdfOptions,
      input,
      ...(salt !== undefined ? { salt } : {}),
    },
  };
}

function normalizeFormatOptions(
  format: CreatePassphraseCipherOptions['format'],
  saltSize: number | undefined,
): CreateDerivedKeyCipherOptions['format'] {
  if (!format) {
    return undefined;
  }

  const formatOptions: FormatOptions & { saltSize?: number } = typeof format === 'string'
    ? { name: format }
    : { ...format };
  if (formatOptions.saltSize === undefined) {
    formatOptions.saltSize = saltSize ?? 8;
  }
  return formatOptions;
}
