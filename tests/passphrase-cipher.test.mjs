import assert from 'node:assert/strict';
import { test } from 'node:test';
import { concatBytes } from '@jscrypto/core';
import { registry } from '@jscrypto/classic';
import { classicHashesPreset } from '@jscrypto/classic/hashes';
import { bytesToHex, bytesToText, hexToBytes, textToBytes } from './helpers/bytes.mjs';

registry.use(classicHashesPreset);

test('passphrase cipher matches CryptoJS OpenSSL AES-CBC output with fixed salt', () => {
  const cipher = registry.createPassphraseCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    passphrase: 'secret',
    kdf: {
      name: 'EvpKDF',
      iterations: 1,
      hash: 'MD5',
    },
    format: 'OpenSSL',
    salt: hexToBytes('0001020304050607'),
  });

  const encrypted = cipher.encrypt(textToBytes('abc'));

  assert.equal(
    bytesToHex(encrypted),
    '53616c7465645f5f00010203040506074c87a9e77ccd8995cc1a9bd212d183c6',
  );
  assert.equal(bytesToText(cipher.decrypt(encrypted)), 'abc');
});

test('passphrase cipher supports PBKDF2 options', () => {
  const cipher = registry.createPassphraseCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    passphrase: 'secret',
    kdf: {
      name: 'PBKDF2',
      iterations: 1000,
      hash: 'SHA256',
    },
    format: 'OpenSSL',
    salt: hexToBytes('0102030405060708'),
  });

  const encrypted = cipher.encrypt(textToBytes('hello'));

  assert.equal(bytesToHex(encrypted.subarray(0, 16)), '53616c7465645f5f0102030405060708');
  assert.equal(bytesToText(cipher.decrypt(encrypted)), 'hello');
});

test('passphrase cipher supports format shorthand', () => {
  const cipher = registry.createPassphraseCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    passphrase: 'secret',
    kdf: 'EvpKDF',
    format: 'OpenSSL',
    salt: hexToBytes('0001020304050607'),
  });

  assert.equal(bytesToText(cipher.decrypt(cipher.encrypt(textToBytes('abc')))), 'abc');
});

test('passphrase cipher streams OpenSSL encryption output', () => {
  const cipher = registry.createPassphraseCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    passphrase: 'secret',
    kdf: {
      name: 'EvpKDF',
      iterations: 1,
      hash: 'MD5',
    },
    format: 'OpenSSL',
    salt: hexToBytes('0001020304050607'),
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

test('passphrase cipher streams OpenSSL decryption input', () => {
  const cipher = registry.createPassphraseCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    passphrase: 'secret',
    kdf: 'EvpKDF',
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
