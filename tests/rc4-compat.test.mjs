import assert from 'node:assert/strict';
import { test } from 'node:test';
import { concatBytes, createRegistry } from '@crypto/core';
import { rc4, rc4Drop } from '@crypto/classic';
import { bytesToHex, bytesToText, hexToBytes, textToBytes } from './helpers/bytes.mjs';

const key = hexToBytes('000102030405060708090a0b0c0d0e0f');

test('RC4 matches CryptoJS upstream test vectors', () => {
  const registry = createRegistry().use(rc4);
  const cases = [
    {
      key: '0123456789abcdef',
      plaintext: '0000000000000000',
      ciphertext: '7494c2e7104b0879',
    },
    {
      key: '618a63d2fb',
      plaintext: 'dcee4cf92c',
      ciphertext: 'f13829c9de',
    },
  ];

  for (const item of cases) {
    const ciphertext = registry.encrypt({
      cipher: 'RC4',
      key: hexToBytes(item.key),
      plaintext: hexToBytes(item.plaintext),
    });

    assert.equal(bytesToHex(ciphertext), item.ciphertext);
  }
});

test('RC4 encrypts and decrypts without mode or padding', () => {
  const registry = createRegistry().use(rc4);
  const plaintext = textToBytes('abc');
  const ciphertext = registry.encrypt({
    cipher: 'RC4',
    key,
    plaintext,
  });

  assert.equal(bytesToHex(ciphertext), '88fe23');
  assert.equal(bytesToText(registry.decrypt({
    cipher: 'RC4',
    key,
    ciphertext,
  })), 'abc');
});

test('RC4 supports byte-based drop option', () => {
  const registry = createRegistry().use(rc4);
  const plaintext = textToBytes('abc');
  const ciphertext = registry.encrypt({
    cipher: 'RC4',
    key,
    plaintext,
    drop: 256,
  });

  assert.equal(bytesToHex(ciphertext), '462268');
  assert.equal(bytesToText(registry.decrypt({
    cipher: 'RC4',
    key,
    ciphertext,
    drop: 256,
  })), 'abc');
});

test('RC4 byte drop can match CryptoJS RC4Drop word drop vectors', () => {
  const registry = createRegistry().use(rc4);
  const ciphertext = registry.encrypt({
    cipher: 'RC4',
    key: hexToBytes('0123456789abcdef'),
    plaintext: hexToBytes('0000000000000000'),
    drop: 8,
  });

  assert.equal(bytesToHex(ciphertext), '0d4bd553328f1efc');
});

test('RC4 streams encryption and decryption', () => {
  const registry = createRegistry().use(rc4);
  const plaintext = textToBytes('中文');
  const encryptor = registry.createEncryptor({
    cipher: 'RC4',
    key,
  });
  const ciphertext = concatBytes(
    encryptor.process(plaintext.subarray(0, 1)),
    encryptor.process(plaintext.subarray(1, 4)),
    encryptor.finalize(plaintext.subarray(4)),
  );

  assert.equal(bytesToHex(ciphertext), '0d24ed1fd165');

  const decryptor = registry.createDecryptor({
    cipher: 'RC4',
    key,
  });
  const decrypted = concatBytes(
    decryptor.process(ciphertext.subarray(0, 2)),
    decryptor.finalize(ciphertext.subarray(2)),
  );

  assert.equal(bytesToText(decrypted), '中文');
});

test('RC4 multipart processing matches CryptoJS upstream test vector', () => {
  const registry = createRegistry().use(rc4);
  const encryptor = registry.createEncryptor({
    cipher: 'RC4',
    key: hexToBytes('0123456789abcdef'),
  });
  const ciphertext = concatBytes(
    encryptor.process(hexToBytes('00000000')),
    encryptor.process(hexToBytes('0000')),
    encryptor.process(hexToBytes('0000')),
    encryptor.finalize(),
  );

  assert.equal(bytesToHex(ciphertext), '7494c2e7104b0879');
});

test('RC4 rejects keys shorter than 40 bits', () => {
  const registry = createRegistry().use(rc4);

  assert.throws(() => registry.encrypt({
    cipher: 'RC4',
    key: new Uint8Array([0]),
    plaintext: textToBytes('abc'),
  }), /greater or equal than 40 bits/);
});

test('RC4Drop defaults to dropping 192 bytes', () => {
  const registry = createRegistry().use(rc4).use(rc4Drop);
  const plaintext = textToBytes('abc');
  const viaRc4Drop = registry.encrypt({
    cipher: 'RC4Drop',
    key,
    plaintext,
  });
  const viaRc4Option = registry.encrypt({
    cipher: 'RC4',
    key,
    plaintext,
    drop: 192,
  });

  assert.deepEqual(viaRc4Drop, viaRc4Option);
});
