import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  ansiX923,
  iso10126,
  iso97971,
  pkcs7,
  zeroPadding,
} from '@jscrypto/paddings';
import { bytesToHex, hexToBytes, textToBytes } from './helpers/bytes.js';

function withDeterministicRandom(callback: () => void) {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
  const originalRandom = Math.random;
  Object.defineProperty(globalThis, 'crypto', {
    configurable: true,
    value: {
      getRandomValues<T extends Uint8Array>(array: T): T {
        return array;
      },
    },
  });
  Math.random = () => 0.999;
  try {
    callback();
  } finally {
    Math.random = originalRandom;
    if (descriptor) {
      Object.defineProperty(globalThis, 'crypto', descriptor);
    } else {
      delete (globalThis as { crypto?: unknown }).crypto;
    }
  }
}

function withNoCryptoRandom(callback: () => void) {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
  const originalRandom = Math.random;
  delete (globalThis as { crypto?: unknown }).crypto;
  Math.random = () => 0.999;
  try {
    callback();
  } finally {
    Math.random = originalRandom;
    if (descriptor) {
      Object.defineProperty(globalThis, 'crypto', descriptor);
    }
  }
}

function withNonZeroCryptoRandom(callback: () => void) {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
  Object.defineProperty(globalThis, 'crypto', {
    configurable: true,
    value: {
      getRandomValues<T extends Uint8Array>(array: T): T {
        array.fill(0xff);
        return array;
      },
    },
  });
  try {
    callback();
  } finally {
    if (descriptor) {
      Object.defineProperty(globalThis, 'crypto', descriptor);
    } else {
      delete (globalThis as { crypto?: unknown }).crypto;
    }
  }
}

test('classic paddings validate edge cases and random fallbacks', () => {
  assert.throws(() => zeroPadding.pad(textToBytes('a'), 0), /blockSize/);
  assert.deepEqual(zeroPadding.pad(textToBytes('abcd'), 4), textToBytes('abcd'));
  assert.deepEqual(zeroPadding.unpad(new Uint8Array([1, 0, 0]), 4), new Uint8Array([1]));

  assert.throws(() => ansiX923.unpad(new Uint8Array([1, 0]), 2), /ANSI X9.23/);
  assert.throws(() => ansiX923.unpad(new Uint8Array([1, 3]), 2), /ANSI X9.23/);
  assert.throws(() => ansiX923.unpad(new Uint8Array([1, 1, 2, 3]), 4), /ANSI X9.23/);

  assert.throws(() => iso10126.pad(textToBytes('a'), 256), /between 1 and 255/);
  assert.throws(() => iso10126.unpad(new Uint8Array([1, 0]), 2), /ISO 10126/);
  assert.throws(() => iso10126.unpad(new Uint8Array([1, 3]), 2), /ISO 10126/);
  assert.equal(bytesToHex(iso97971.pad(textToBytes('abc'), 4)), '61626380');
  assert.throws(() => pkcs7.unpad(new Uint8Array([1, 3]), 2), /PKCS#7/);
  assert.throws(() => pkcs7.unpad(new Uint8Array([2, 3]), 2), /PKCS#7/);
  assert.throws(() => pkcs7.unpad(new Uint8Array([1, 2]), 2), /PKCS#7/);

  withDeterministicRandom(() => {
    assert.equal(bytesToHex(iso10126.pad(textToBytes('abc'), 4)), '61626301');
    assert.equal(bytesToHex(iso10126.pad(textToBytes('a'), 4)), '61ffff03');
  });
  withNoCryptoRandom(() => {
    assert.equal(bytesToHex(iso10126.pad(textToBytes('a'), 4)), '61ffff03');
  });
  withNonZeroCryptoRandom(() => {
    const padded = iso10126.pad(textToBytes('abc'), 16);
    assert.equal(padded.length, 16);
    assert.equal(padded[padded.length - 1], 13);
  });
});

test('padding modules cover pad and unpad success paths', () => {
  assert.deepEqual(iso97971.unpad(iso97971.pad(textToBytes('abc'), 16), 16), textToBytes('abc'));
  assert.deepEqual(ansiX923.unpad(ansiX923.pad(textToBytes('abc'), 16), 16), textToBytes('abc'));
  assert.deepEqual(iso10126.unpad(iso10126.pad(textToBytes('abc'), 16), 16), textToBytes('abc'));
  assert.equal(zeroPadding.pad(textToBytes('abc'), 4).length, 4);
  assert.throws(
    () => iso97971.unpad(hexToBytes('61626300000000000000000000000000'), 16),
    /Invalid ISO\/IEC 9797-1/,
  );
  assert.throws(
    () => ansiX923.unpad(hexToBytes('6162630100000000000000000000010d'), 16),
    /Invalid ANSI X9.23/,
  );
});
