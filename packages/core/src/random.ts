const MAX_RANDOM_CHUNK = 65536;

export function randomBytes(length: number): Uint8Array {
  assertNonNegativeInteger(length, 'length');
  const bytes = new Uint8Array(length);
  if (bytes.length === 0) {
    return bytes;
  }

  const crypto = globalThis as typeof globalThis & {
    crypto?: {
      getRandomValues<T extends Uint8Array>(array: T): T;
    };
  };

  if (crypto.crypto?.getRandomValues) {
    const getRandomValues = crypto.crypto.getRandomValues.bind(crypto.crypto);
    for (let offset = 0; offset < bytes.length; offset += MAX_RANDOM_CHUNK) {
      getRandomValues(bytes.subarray(offset, Math.min(offset + MAX_RANDOM_CHUNK, bytes.length)));
    }
    return bytes;
  }

  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Math.floor(Math.random() * 256);
  }
  return bytes;
}

function assertNonNegativeInteger(value: number, label: string): void {
  if (!Number.isInteger(value) || value < 0) {
    throw new RangeError(`${label} must be a non-negative integer.`);
  }
}
