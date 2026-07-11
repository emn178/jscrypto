import assert from 'node:assert/strict';
import { test } from 'node:test';
import { concatBytes, createRegistry } from '@jscrypto/core';
import { aes, cfb, ctr, noPadding, ofb } from '@jscrypto/classic';
import { bytesToHex, bytesToText, hexToBytes, textToBytes } from './helpers/bytes.mjs';

const key = hexToBytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
const iv = hexToBytes('000102030405060708090a0b0c0d0e0f');
const plaintext = textToBytes('abc');

const cases = [
  ['CFB', cfb],
  ['CTR', ctr],
  ['OFB', ofb],
];

for (const [modeName, mode] of cases) {
  test(`AES-256-${modeName} streams encryption and decryption`, () => {
    const registry = createRegistry()
      .use(aes)
      .use(mode)
      .use(noPadding);

    const encryptor = registry.createEncryptor({
      cipher: 'AES',
      mode: modeName,
      padding: 'NoPadding',
      key,
      iv,
    });
    const ciphertext = concatBytes(
      encryptor.process(plaintext.subarray(0, 1)),
      encryptor.process(plaintext.subarray(1, 2)),
      encryptor.finalize(plaintext.subarray(2)),
    );

    assert.equal(bytesToHex(ciphertext), '3b0c67');

    const decryptor = registry.createDecryptor({
      cipher: 'AES',
      mode: modeName,
      padding: 'NoPadding',
      key,
      iv,
    });
    const decrypted = concatBytes(
      decryptor.process(ciphertext.subarray(0, 1)),
      decryptor.finalize(ciphertext.subarray(1)),
    );

    assert.equal(bytesToText(decrypted), 'abc');
  });
}

test('AES-256-CTR handles data longer than one block', () => {
  const registry = createRegistry()
    .use(aes)
    .use(ctr)
    .use(noPadding);
  const input = textToBytes('12345678901234561234567890123456');
  const encryptor = registry.createEncryptor({
    cipher: 'AES',
    mode: 'CTR',
    padding: 'NoPadding',
    key,
    iv,
  });
  const ciphertext = concatBytes(
    encryptor.process(input.subarray(0, 7)),
    encryptor.process(input.subarray(7, 19)),
    encryptor.finalize(input.subarray(19)),
  );

  const decryptor = registry.createDecryptor({
    cipher: 'AES',
    mode: 'CTR',
    padding: 'NoPadding',
    key,
    iv,
  });
  const decrypted = concatBytes(
    decryptor.process(ciphertext.subarray(0, 5)),
    decryptor.process(ciphertext.subarray(5, 23)),
    decryptor.finalize(ciphertext.subarray(23)),
  );

  assert.equal(bytesToText(decrypted), bytesToText(input));
});
