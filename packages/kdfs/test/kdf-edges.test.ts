import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createRegistry } from '@jscrypto/core';
import { md5, sha256 } from '@jscrypto/hashes';
import { deriveEvpKdf, derivePbkdf2, evpKdf, pbkdf2 } from '../src/index.js';

test('classic kdfs validate inputs and missing registered hashes', () => {
  assert.throws(() => derivePbkdf2({ input: 'x', salt: 's', iterations: 0, length: 16, hash: sha256 }), /PBKDF2 iterations/);
  assert.throws(() => derivePbkdf2({ input: 'x', salt: 's', iterations: 1, length: 0, hash: sha256 }), /PBKDF2 length/);
  assert.throws(() => derivePbkdf2({ input: 'x', iterations: 1, length: 16, hash: sha256 } as Parameters<typeof derivePbkdf2>[0]), /requires salt/);
  assert.throws(() => deriveEvpKdf({ input: 'x', salt: 's', iterations: 0, length: 16, hash: md5 }), /EvpKDF iterations/);
  assert.throws(() => deriveEvpKdf({ input: 'x', salt: 's', length: 0, hash: md5 }), /EvpKDF length/);
  assert.throws(() => deriveEvpKdf({ input: 'x', length: 16, hash: md5 } as Parameters<typeof deriveEvpKdf>[0]), /requires salt/);
  assert.equal(derivePbkdf2({
    input: new Uint8Array(65),
    salt: 's',
    iterations: 1,
    length: 16,
    hash: sha256,
  }).length, 16);
  const registry = createRegistry([evpKdf, pbkdf2]);
  assert.throws(() => evpKdf.derive({ input: 'x', salt: 's', length: 16 }, { getHash: registry.getHash.bind(registry) }), /Hash not registered: MD5/);
  assert.throws(() => pbkdf2.derive({ input: 'x', salt: 's', iterations: 1, length: 16 }, { getHash: registry.getHash.bind(registry) }), /Hash not registered: SHA256/);
});
