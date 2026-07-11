import assert from 'node:assert/strict';
import { test } from 'node:test';
import { concatBytes, createRegistry } from '@jscrypto/core';
import { aes, ecb, pkcs7 } from '@jscrypto/classic';
import { bytesToHex, bytesToText, hexToBytes, textToBytes } from './helpers/bytes.mjs';

test('AES-256-ECB streams encryption and decryption with Pkcs7', () => {
  const key = hexToBytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
  const plaintext = textToBytes('abc');
  const registry = createRegistry()
    .use(aes)
    .use(ecb)
    .use(pkcs7);

  const encryptor = registry.createEncryptor({
    cipher: 'AES',
    mode: 'ECB',
    padding: 'Pkcs7',
    key,
  });
  const ciphertext = concatBytes(
    encryptor.process(plaintext.subarray(0, 1)),
    encryptor.process(plaintext.subarray(1)),
    encryptor.finalize(),
  );

  assert.equal(bytesToHex(ciphertext), 'd1d00088422280392f0e2568ada86436');

  const decryptor = registry.createDecryptor({
    cipher: 'AES',
    mode: 'ECB',
    padding: 'Pkcs7',
    key,
  });
  const decrypted = concatBytes(
    decryptor.process(ciphertext.subarray(0, 4)),
    decryptor.process(ciphertext.subarray(4)),
    decryptor.finalize(),
  );

  assert.equal(bytesToText(decrypted), 'abc');
});
