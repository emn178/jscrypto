import assert from 'node:assert/strict';
import { test } from 'node:test';
import { concatBytes } from '@jscrypto/core';
import { createAllRegistry } from '../src/all.js';
import { bytesToHex, bytesToText, hexToBytes, textToBytes } from './helpers/bytes.js';

function createCompatRegistry() {
  return createAllRegistry();
}

test('derived-key cipher matches CryptoJS OpenSSL AES-CBC output with fixed salt', () => {
  const registry = createCompatRegistry();
  const cipher = registry.createDerivedKeyCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    kdf: {
      name: 'EvpKDF',
      input: 'secret',
      salt: hexToBytes('0001020304050607'),
      iterations: 1,
      hash: 'MD5',
    },
    format: 'OpenSSL',
  });

  const encrypted = cipher.encrypt(textToBytes('abc'));

  assert.equal(
    bytesToHex(encrypted),
    '53616c7465645f5f00010203040506074c87a9e77ccd8995cc1a9bd212d183c6',
  );
  assert.equal(bytesToText(cipher.decrypt(encrypted)), 'abc');
});

test('derived-key cipher supports PBKDF2 options', () => {
  const registry = createCompatRegistry();
  const cipher = registry.createDerivedKeyCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    kdf: {
      name: 'PBKDF2',
      input: 'secret',
      salt: hexToBytes('0102030405060708'),
      iterations: 1000,
      hash: 'SHA256',
    },
    format: 'OpenSSL',
  });

  const encrypted = cipher.encrypt(textToBytes('hello'));

  assert.equal(bytesToHex(encrypted.subarray(0, 16)), '53616c7465645f5f0102030405060708');
  assert.equal(bytesToText(cipher.decrypt(encrypted)), 'hello');
});

test('derived-key cipher supports format shorthand', () => {
  const registry = createCompatRegistry();
  const cipher = registry.createDerivedKeyCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    kdf: {
      name: 'EvpKDF',
      input: 'secret',
      salt: hexToBytes('0001020304050607'),
    },
    format: 'OpenSSL',
  });

  assert.equal(bytesToText(cipher.decrypt(cipher.encrypt(textToBytes('abc')))), 'abc');
});

test('derived-key cipher streams OpenSSL encryption output', () => {
  const registry = createCompatRegistry();
  const cipher = registry.createDerivedKeyCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    kdf: {
      name: 'EvpKDF',
      input: 'secret',
      salt: hexToBytes('0001020304050607'),
      iterations: 1,
      hash: 'MD5',
    },
    format: 'OpenSSL',
  });
  const encryptor = cipher.createEncryptor();

  const encrypted = concatBytes(
    encryptor.process(textToBytes('a')),
    encryptor.process(textToBytes('b')),
    encryptor.finalize(textToBytes('c')),
  );

  assert.equal(
    bytesToHex(encrypted),
    '53616c7465645f5f00010203040506074c87a9e77ccd8995cc1a9bd212d183c6',
  );
});

test('derived-key cipher streams OpenSSL decryption input', () => {
  const registry = createCompatRegistry();
  const cipher = registry.createDerivedKeyCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    kdf: {
      name: 'EvpKDF',
      input: 'secret',
      hash: 'MD5',
    },
    format: 'OpenSSL',
  });
  const encrypted = hexToBytes('53616c7465645f5f00010203040506074c87a9e77ccd8995cc1a9bd212d183c6');
  const decryptor = cipher.createDecryptor();

  const decrypted = concatBytes(
    decryptor.process(encrypted.subarray(0, 5)),
    decryptor.process(encrypted.subarray(5, 16)),
    decryptor.process(encrypted.subarray(16, 23)),
    decryptor.finalize(encrypted.subarray(23)),
  );

  assert.equal(bytesToText(decrypted), 'abc');
});
