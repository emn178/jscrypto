import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createRegistry } from '@crypto/core';
import { ansiX923, cbc, cfb, ctr, des, ecb, iso97971, noPadding, ofb, pkcs7, zeroPadding } from '@crypto/classic';
import { bytesToHex, bytesToText, hexToBytes, textToBytes } from './helpers/bytes.mjs';

const key = hexToBytes('0001020304050607');
const iv = hexToBytes('0001020304050607');

function createDesRegistry() {
  return createRegistry()
    .use(des)
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

test('DES-CBC encrypts and decrypts with Pkcs7', () => {
  const registry = createDesRegistry();
  const plaintext = textToBytes('abc');
  const ciphertext = registry.encrypt({
    cipher: 'DES',
    mode: 'CBC',
    padding: 'Pkcs7',
    key,
    iv,
    plaintext,
  });

  assert.equal(bytesToHex(ciphertext), 'e0ba008ae311fa79');
  assert.equal(bytesToText(registry.decrypt({
    cipher: 'DES',
    mode: 'CBC',
    padding: 'Pkcs7',
    key,
    iv,
    ciphertext,
  })), 'abc');
});

test('DES modes match online-tools vectors', () => {
  const registry = createDesRegistry();
  const plaintext = textToBytes('abc');
  const cases = [
    ['CBC', 'Pkcs7', 'e0ba008ae311fa79'],
    ['CFB', 'NoPadding', '80d025'],
    ['CTR', 'NoPadding', '80d025'],
    ['OFB', 'NoPadding', '80d025'],
    ['ECB', 'Pkcs7', '9a9e8906315ae06f'],
  ];

  for (const [mode, padding, expected] of cases) {
    const ciphertext = registry.encrypt({
      cipher: 'DES',
      mode,
      padding,
      key,
      iv,
      plaintext,
    });
    assert.equal(bytesToHex(ciphertext), expected);
  }
});

test('DES paddings match online-tools vectors', () => {
  const registry = createDesRegistry();
  const cases = [
    ['Pkcs7', textToBytes('abc'), 'e0ba008ae311fa79'],
    ['Iso97971', textToBytes('abc'), 'cbf24c1395e9804f'],
    ['AnsiX923', textToBytes('abc'), '15a4dc19d06fd3dd'],
    ['ZeroPadding', textToBytes('abc'), 'ca2b21adf68d3ac2'],
    ['NoPadding', textToBytes('12345678'), 'db756d33ac358ffc'],
  ];

  for (const [padding, plaintext, expected] of cases) {
    const ciphertext = registry.encrypt({
      cipher: 'DES',
      mode: 'CBC',
      padding,
      key,
      iv,
      plaintext,
    });
    assert.equal(bytesToHex(ciphertext), expected);
  }
});
