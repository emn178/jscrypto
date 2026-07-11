import assert from 'node:assert/strict';
import { test } from 'node:test';
import { concatBytes } from '@crypto/core';
import { createClassicRegistry, registry } from '@crypto/classic';
import { bytesToHex, bytesToText, hexToBytes, textToBytes } from './helpers/bytes.mjs';

test('cipher facade encrypts and decrypts one-shot calls', () => {
  const key = hexToBytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
  const iv = hexToBytes('000102030405060708090a0b0c0d0e0f');
  const cipher = createClassicRegistry().createCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    key,
    iv,
  });

  const first = cipher.encrypt(textToBytes('abc'));
  const second = cipher.encrypt(textToBytes('abc'));

  assert.equal(bytesToHex(first), 'e98b50daffee0c8e527bba7859e83713');
  assert.deepEqual(second, first);
  assert.equal(bytesToText(cipher.decrypt(first)), 'abc');
});

test('classic singleton registry creates reusable cipher facades', () => {
  const key = hexToBytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
  const iv = hexToBytes('000102030405060708090a0b0c0d0e0f');
  const cipher = registry.createCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    key,
    iv,
  });

  assert.equal(bytesToText(cipher.decrypt(cipher.encrypt(textToBytes('abc')))), 'abc');
});

test('cipher facade creates independent streaming transforms', () => {
  const key = hexToBytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
  const iv = hexToBytes('000102030405060708090a0b0c0d0e0f');
  const cipher = createClassicRegistry().createCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    key,
    iv,
  });

  const encryptor = cipher.createEncryptor();
  const ciphertext = concatBytes(
    encryptor.process(textToBytes('a')),
    encryptor.process(textToBytes('bc')),
    encryptor.finalize(),
  );

  const decryptor = cipher.createDecryptor();
  const plaintext = concatBytes(
    decryptor.process(ciphertext.subarray(0, 7)),
    decryptor.process(ciphertext.subarray(7)),
    decryptor.finalize(),
  );

  assert.equal(bytesToHex(ciphertext), 'e98b50daffee0c8e527bba7859e83713');
  assert.equal(bytesToText(plaintext), 'abc');
});
