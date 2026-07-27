import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomBytes } from '@jscrypto/core';

test('randomBytes returns requested byte length', () => {
  const bytes = randomBytes(16);
  assert.equal(bytes.length, 16);
  assert.ok(bytes instanceof Uint8Array);
});

test('randomBytes supports length zero', () => {
  const bytes = randomBytes(0);
  assert.equal(bytes.length, 0);
  assert.ok(bytes instanceof Uint8Array);
});

test('randomBytes rejects invalid lengths', () => {
  assert.throws(() => randomBytes(-1), /non-negative integer/);
  assert.throws(() => randomBytes(1.5), /non-negative integer/);
});

test('randomBytes prefers crypto.getRandomValues when available', () => {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
  Object.defineProperty(globalThis, 'crypto', {
    configurable: true,
    value: {
      getRandomValues(array) {
        array.fill(0xab);
        return array;
      },
    },
  });
  try {
    assert.deepEqual(randomBytes(4), new Uint8Array([0xab, 0xab, 0xab, 0xab]));
  } finally {
    if (descriptor) {
      Object.defineProperty(globalThis, 'crypto', descriptor);
    } else {
      delete globalThis.crypto;
    }
  }
});

test('randomBytes falls back to Math.random when crypto is unavailable', () => {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
  const originalRandom = Math.random;
  delete globalThis.crypto;
  Math.random = () => 0.5;
  try {
    const bytes = randomBytes(3);
    assert.equal(bytes.length, 3);
    assert.deepEqual(bytes, new Uint8Array([128, 128, 128]));
  } finally {
    Math.random = originalRandom;
    if (descriptor) {
      Object.defineProperty(globalThis, 'crypto', descriptor);
    }
  }
});

test('randomBytes fills large buffers in 65536-byte getRandomValues chunks', () => {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
  const chunkSizes = [];
  Object.defineProperty(globalThis, 'crypto', {
    configurable: true,
    value: {
      getRandomValues(array) {
        if (array.length > 65536) {
          throw new Error('QuotaExceededError');
        }
        chunkSizes.push(array.length);
        array.fill(0xcd);
        return array;
      },
    },
  });
  try {
    const bytes = randomBytes(65536 + 3);
    assert.equal(bytes.length, 65536 + 3);
    assert.deepEqual(chunkSizes, [65536, 3]);
    assert.equal(bytes[0], 0xcd);
    assert.equal(bytes[65536], 0xcd);
    assert.equal(bytes[65538], 0xcd);
  } finally {
    if (descriptor) {
      Object.defineProperty(globalThis, 'crypto', descriptor);
    } else {
      delete globalThis.crypto;
    }
  }
});
