import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createRegistry } from '@jscrypto/core';
import { createRc4Transform, rc4, rc4Drop, rc4Preset } from '../src/rc4.js';
import { bytesToHex, textToBytes } from './helpers/bytes.js';

test('RC4 option validation and defaults cover stream branches', () => {
  assert.equal(bytesToHex(createRc4Transform(textToBytes('secret')).finalize()), '');
  const direct = createRc4Transform(textToBytes('secret'));
  direct.finalize(textToBytes('a'));
  assert.throws(() => direct.process(textToBytes('b')), /already finalized/);
  assert.throws(() => createRc4Transform(textToBytes('secret'), -1), /non-negative/);

  const registry = createRegistry([rc4, rc4Drop]);
  assert.equal(registry.createCipher({ cipher: 'RC4', key: textToBytes('secret') }).encrypt(textToBytes('x')).length, 1);
  assert.equal(registry.createCipher({ cipher: 'RC4Drop', key: textToBytes('secret') }).decrypt(textToBytes('x')).length, 1);
});

test('rc4Preset registers RC4 and RC4Drop', () => {
  assert.deepEqual(
    [...rc4Preset.components()].map((component) => component.name),
    ['RC4', 'RC4Drop'],
  );
});
