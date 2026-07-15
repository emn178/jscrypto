import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createRegistry } from '@jscrypto/core';
import { ansiX923, cbc, cfb, createTripleDesCipher, ctr, ecb, iso97971, noPadding, ofb, pkcs7, tripleDes, zeroPadding } from '@jscrypto/classic';
import { bytesToHex, bytesToText, hexToBytes, textToBytes } from './helpers/bytes.mjs';

const key = hexToBytes('000102030405060708090a0b0c0d0e0f1011121314151617');
const iv = hexToBytes('0001020304050607');

function createTripleDesRegistry() {
  return createRegistry()
    .use(tripleDes)
    .use(cbc)
    .use(cfb)
    .use(ctr)
    .use(ecb)
    .use(ofb)
    .use(pkcs7)
    .use(iso97971)
    .use(ansiX923)
    .use(zeroPadding)
    .use(noPadding);
}

test('TripleDES encrypts and decrypts two-key and three-key block vectors', () => {
  const plaintext = hexToBytes('0000000000000000');
  const cases = [
    ['0123456789abcdeffedcba9876543210', '08d7b4fb629d0885'],
    ['0123456789abcdef23456789abcdef01456789abcdef0123', '4eba739c998bcb60'],
  ];

  for (const [keyHex, expected] of cases) {
    const cipher = createTripleDesCipher(hexToBytes(keyHex));
    const ciphertext = hexToBytes(expected);

    assert.equal(bytesToHex(cipher.encryptBlock(plaintext)), expected);
    assert.equal(bytesToHex(cipher.decryptBlock(ciphertext)), bytesToHex(plaintext));
  }
});

test('TripleDES-CBC encrypts and decrypts with Pkcs7', () => {
  const registry = createTripleDesRegistry();
  const plaintext = textToBytes('abc');
  const ciphertext = registry.encrypt({
    cipher: 'TripleDES',
    mode: 'CBC',
    padding: 'Pkcs7',
    key,
    iv,
    plaintext,
  });

  assert.equal(bytesToHex(ciphertext), '906630fcc5fec0d8');
  assert.equal(bytesToText(registry.decrypt({
    cipher: 'TripleDES',
    mode: 'CBC',
    padding: 'Pkcs7',
    key,
    iv,
    ciphertext,
  })), 'abc');
});

test('TripleDES key sizes match online-tools vectors', () => {
  const registry = createTripleDesRegistry();
  const plaintext = textToBytes('abc');
  const cases = [
    ['000102030405060708090a0b0c0d0e0f', '13433a7cc73189df'],
    ['000102030405060708090a0b0c0d0e0f1011121314151617', '906630fcc5fec0d8'],
  ];

  for (const [keyHex, expected] of cases) {
    const ciphertext = registry.encrypt({
      cipher: 'TripleDES',
      mode: 'CBC',
      padding: 'Pkcs7',
      key: hexToBytes(keyHex),
      iv,
      plaintext,
    });
    assert.equal(bytesToHex(ciphertext), expected);
  }
});

test('TripleDES modes match online-tools vectors', () => {
  const registry = createTripleDesRegistry();
  const plaintext = textToBytes('abc');
  const cases = [
    ['CBC', 'Pkcs7', '906630fcc5fec0d8'],
    ['CFB', 'NoPadding', '398f47'],
    ['CTR', 'NoPadding', '398f47'],
    ['OFB', 'NoPadding', '398f47'],
    ['ECB', 'Pkcs7', '60704942e0e8cd38'],
  ];

  for (const [mode, padding, expected] of cases) {
    const ciphertext = registry.encrypt({
      cipher: 'TripleDES',
      mode,
      padding,
      key,
      iv,
      plaintext,
    });
    assert.equal(bytesToHex(ciphertext), expected);
  }
});

test('TripleDES paddings match online-tools vectors', () => {
  const registry = createTripleDesRegistry();
  const cases = [
    ['Pkcs7', textToBytes('abc'), '906630fcc5fec0d8'],
    ['Iso97971', textToBytes('abc'), 'f887f9a316ceb529'],
    ['AnsiX923', textToBytes('abc'), '051dcce6d89ee38d'],
    ['ZeroPadding', textToBytes('abc'), '33469216622a6b7f'],
    ['NoPadding', textToBytes('12345678'), '904aafeb95e273a9'],
  ];

  for (const [padding, plaintext, expected] of cases) {
    const ciphertext = registry.encrypt({
      cipher: 'TripleDES',
      mode: 'CBC',
      padding,
      key,
      iv,
      plaintext,
    });
    assert.equal(bytesToHex(ciphertext), expected);
  }
});
