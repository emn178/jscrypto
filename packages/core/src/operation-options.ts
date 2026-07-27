/**
 * Per-operation options for cipher facades.
 * Core only forwards these to mode/cipher components; mode-specific keys such as
 * `nonce`, `aad`, `tag`, and `tagLength` belong to the mode implementation.
 */
export type CipherOperationOptions = Record<string, unknown>;

export interface DerivedKeyCipherOperationOptions extends CipherOperationOptions {
  salt?: Uint8Array | string | null;
}

/** Keys that must not be overridden by operation options. */
export const RESERVED_OPERATION_OPTION_KEYS = [
  'cipher',
  'mode',
  'padding',
  'key',
  'kdf',
  'format',
  'keySize',
  'ivSize',
  'passphrase',
  'saltSize',
] as const;

export function assertNoReservedOperationOptions(
  options: Record<string, unknown> | undefined,
): void {
  if (!options) {
    return;
  }
  for (const key of RESERVED_OPERATION_OPTION_KEYS) {
    if (Object.prototype.hasOwnProperty.call(options, key)) {
      throw new Error(`operation options must not override reserved key: ${key}`);
    }
  }
}
