import assert from 'node:assert/strict';
import { test } from 'node:test';
import { concatBytes, createRegistry } from '@jscrypto/core';
import { aes, cbc, noPadding } from '@jscrypto/classic';
import { bytesToHex, bytesToText, hexToBytes, textToBytes } from './helpers/bytes.mjs';

test('AES-256-CBC encrypts and decrypts with NoPadding', () => {
  const key = hexToBytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
  const iv = hexToBytes('000102030405060708090a0b0c0d0e0f');
  const plaintext = textToBytes('1234567890123456');

  const registry = createRegistry()
    .use(aes)
    .use(cbc)
    .use(noPadding);

  const ciphertext = registry.encrypt({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'NoPadding',
    key,
    iv,
    plaintext,
  });

  assert.equal(bytesToHex(ciphertext), 'b9b4ff87297a91139a3eecdcecfd8fdf');

  const decrypted = registry.decrypt({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'NoPadding',
    key,
    iv,
    ciphertext,
  });
  assert.equal(bytesToText(decrypted), '1234567890123456');
});

test('NoPadding rejects partial blocks', () => {
  assert.throws(() => noPadding.pad(new Uint8Array([1, 2, 3]), 16), /multiple of the block size/);
});

test('AES-256-CBC streams encryption and decryption with NoPadding', () => {
  const key = hexToBytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
  const iv = hexToBytes('000102030405060708090a0b0c0d0e0f');
  const plaintext = textToBytes('1234567890123456');
  const registry = createRegistry()
    .use(aes)
    .use(cbc)
    .use(noPadding);

  const encryptor = registry.createEncryptor({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'NoPadding',
    key,
    iv,
  });
  const ciphertext = concatBytes(
    encryptor.process(plaintext.subarray(0, 3)),
    encryptor.process(plaintext.subarray(3, 9)),
    encryptor.process(plaintext.subarray(9)),
    encryptor.finalize(),
  );

  assert.equal(bytesToHex(ciphertext), 'b9b4ff87297a91139a3eecdcecfd8fdf');

  const decryptor = registry.createDecryptor({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'NoPadding',
    key,
    iv,
  });
  const decrypted = concatBytes(
    decryptor.process(ciphertext.subarray(0, 5)),
    decryptor.process(ciphertext.subarray(5, 12)),
    decryptor.process(ciphertext.subarray(12)),
    decryptor.finalize(),
  );

  assert.equal(bytesToText(decrypted), '1234567890123456');
});

test('streaming NoPadding encryption rejects partial final blocks', () => {
  const key = hexToBytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
  const iv = hexToBytes('000102030405060708090a0b0c0d0e0f');
  const registry = createRegistry()
    .use(aes)
    .use(cbc)
    .use(noPadding);
  const encryptor = registry.createEncryptor({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'NoPadding',
    key,
    iv,
  });

  assert.deepEqual(encryptor.process(new Uint8Array([1, 2, 3])), new Uint8Array());
  assert.throws(() => encryptor.finalize(), /multiple of the block size/);
});
