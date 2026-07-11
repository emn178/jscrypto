import assert from 'node:assert/strict';
import { test } from 'node:test';
import { concatBytes, createRegistry } from '@jscrypto/core';
import { aes, cbc, pkcs7 } from '@jscrypto/classic';
import { bytesToHex, bytesToText, hexToBytes, textToBytes } from './helpers/bytes.mjs';

test('AES-256-CBC streams encryption and decryption with Pkcs7', () => {
  const key = hexToBytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
  const iv = hexToBytes('000102030405060708090a0b0c0d0e0f');
  const plaintext = textToBytes('abc');
  const registry = createRegistry()
    .use(aes)
    .use(cbc)
    .use(pkcs7);

  const encryptor = registry.createEncryptor({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    key,
    iv,
  });
  const ciphertext = concatBytes(
    encryptor.process(plaintext.subarray(0, 1)),
    encryptor.process(plaintext.subarray(1)),
    encryptor.finalize(),
  );

  assert.equal(bytesToHex(ciphertext), 'e98b50daffee0c8e527bba7859e83713');

  const decryptor = registry.createDecryptor({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    key,
    iv,
  });
  const decrypted = concatBytes(
    decryptor.process(ciphertext.subarray(0, 3)),
    decryptor.process(ciphertext.subarray(3, 11)),
    decryptor.process(ciphertext.subarray(11)),
    decryptor.finalize(),
  );

  assert.equal(bytesToText(decrypted), 'abc');
});

test('AES-256-CBC Pkcs7 decrypt rejects invalid padding', () => {
  const key = hexToBytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
  const iv = hexToBytes('000102030405060708090a0b0c0d0e0f');
  const ciphertext = hexToBytes('e98b50daffee0c8e527bba7859e83712');
  const registry = createRegistry()
    .use(aes)
    .use(cbc)
    .use(pkcs7);
  const decryptor = registry.createDecryptor({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    key,
    iv,
  });

  assert.deepEqual(decryptor.process(ciphertext), new Uint8Array());
  assert.throws(() => decryptor.finalize(), /Invalid PKCS#7/);
});
