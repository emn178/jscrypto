import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  CryptoError,
  DuplicateComponentError,
  MissingComponentError,
  assertBlockMultiple,
  assertBlockSize,
  assertBytes,
  assertIv,
  assertNoReservedOperationOptions,
  assertPaddedInput,
  concatBytes,
  createRegistry,
  equalBytes,
  getBlockPaddingLength,
  xorBytes,
} from '@jscrypto/core';
import { aes, cbc, evpKdf, opensslFormat, pkcs7, rc4 } from '@jscrypto/suite';
import { classicHashesPreset, md5 } from '@jscrypto/hashes';
import { bytesToText, hexToBytes, textToBytes } from './helpers/bytes.js';

const key = hexToBytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
const iv = hexToBytes('000102030405060708090a0b0c0d0e0f');

test('core helpers cover error branches', () => {
  assert.deepEqual(concatBytes(new Uint8Array([1]), new Uint8Array([2])), new Uint8Array([1, 2]));
  assert.equal(equalBytes(new Uint8Array([1]), new Uint8Array([1, 2])), false);
  assert.equal(equalBytes(new Uint8Array([1]), new Uint8Array([2])), false);
  assert.deepEqual(xorBytes(new Uint8Array([1]), new Uint8Array([3])), new Uint8Array([2]));
  assert.equal(getBlockPaddingLength(4, 4), 4);
  assert.equal(getBlockPaddingLength(3, 4), 1);

  assert.throws(() => xorBytes(new Uint8Array([1]), new Uint8Array([1, 2])), /same length/);
  assert.throws(() => assertBytes([], 'value'), /Uint8Array/);
  assert.throws(() => assertBlockSize(0), /positive integer/);
  assert.throws(() => assertBlockSize(2, { max: 1 }), /between 1 and 1/);
  assert.throws(() => assertBlockMultiple(new Uint8Array([1]), 2, 'Test'), /multiple/);
  assert.throws(() => assertPaddedInput(new Uint8Array(), 2, 'Test'), /Invalid Test/);
  assert.throws(() => assertIv(16, undefined, 'CBC'), /requires an IV/);
  assert.throws(() => assertIv(16, new Uint8Array(8), 'CBC'), /IV length/);
  assertNoReservedOperationOptions(undefined);
  assertNoReservedOperationOptions({});
});

test('registry covers duplicate, missing, list, constructor, one-shot, and transform APIs', () => {
  const registry = createRegistry([aes, cbc, pkcs7]);

  assert.equal(registry.has('cipher', 'AES'), true);
  assert.equal(registry.has('mode', 'ECB'), false);
  assert.equal(registry.list().length, 3);
  assert.equal(registry.list('cipher').length, 1);
  registry.useHash(md5);
  assert.equal(registry.getHash('md-5'), md5);
  assert.throws(() => registry.use(aes), DuplicateComponentError);
  assert.throws(() => registry.get('mode', 'ECB'), MissingComponentError);

  const plaintext = textToBytes('abc');
  const ciphertext = registry.encrypt({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    key,
    iv,
    plaintext,
  });
  assert.equal(bytesToText(registry.decrypt({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    key,
    iv,
    ciphertext,
  })), 'abc');

  const encryptor = registry.createEncryptor({ cipher: 'AES', mode: 'CBC', padding: 'Pkcs7', key, iv });
  encryptor.finalize(plaintext);
  assert.throws(() => encryptor.process(plaintext), /already finalized/);

  const decryptor = registry.createDecryptor({ cipher: 'AES', mode: 'CBC', padding: 'Pkcs7', key, iv });
  decryptor.finalize(ciphertext);
  assert.throws(() => decryptor.finalize(), /already finalized/);
});

test('error classes expose stable names and messages', () => {
  assert.equal(new CryptoError('x').name, 'CryptoError');
  assert.equal(new DuplicateComponentError('cipher', 'AES').message, 'Component already registered: cipher:AES');
  assert.equal(new MissingComponentError('mode', 'CBC').name, 'MissingComponentError');
});

test('block transform option and pending-input errors are surfaced', () => {
  const registry = createRegistry([aes, cbc, pkcs7]);

  assert.throws(() => registry.createEncryptor({ cipher: 'AES', padding: 'Pkcs7', key, iv }), /requires a mode/);
  assert.throws(() => registry.createEncryptor({ cipher: 'AES', mode: 'CBC', key, iv }), /requires padding/);
  assert.throws(() => registry.createCipher({ cipher: 'AES', mode: 'CBC', padding: 'Pkcs7', key, iv: new Uint8Array(8) }).encrypt(textToBytes('a')), /IV length/);

  const ciphertext = registry.encrypt({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    key,
    iv,
    plaintext: textToBytes('abc'),
  });
  assert.throws(() => registry.createDecryptor({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    key,
    iv,
  }).finalize(ciphertext.subarray(0, 3)), /Invalid PKCS#7/);
});

test('stream transforms reject calls after finalize', () => {
  const registry = createRegistry([rc4]);
  const cipher = registry.createCipher({ cipher: 'RC4', key: textToBytes('secret') });

  const encryptor = cipher.createEncryptor();
  encryptor.finalize(textToBytes('a'));
  assert.throws(() => encryptor.process(textToBytes('b')), /already finalized/);

  const decryptor = cipher.createDecryptor();
  decryptor.finalize(textToBytes('a'));
  assert.throws(() => decryptor.finalize(), /already finalized/);

  const directDecryptor = registry.createDecryptor({ cipher: 'RC4', key: textToBytes('secret') });
  assert.equal(directDecryptor.finalize(textToBytes('x')).length, 1);
  assert.equal(registry.createDecryptor({ cipher: 'RC4', key: textToBytes('secret') }).process(textToBytes('x')).length, 1);
  assert.equal(registry.createDecryptor({ cipher: 'RC4', key: textToBytes('secret') }).finalize().length, 0);

  const streamEncryptor = cipher.createEncryptor();
  assert.equal(streamEncryptor.finalize().length, 0);
});

test('block encryptor process returns empty output before a full block is buffered', () => {
  const registry = createRegistry([aes, cbc, pkcs7]);
  const encryptor = registry.createEncryptor({ cipher: 'AES', mode: 'CBC', padding: 'Pkcs7', key, iv });
  assert.equal(encryptor.process(textToBytes('a')).length, 0);
  assert.ok(encryptor.process(textToBytes('abcdefghijklmnop')).length > 0);
  assert.ok(encryptor.finalize().length > 0);
});

test('OpenSSL derived-key decrypt streams partial headers and subsequent chunks', () => {
  const registry = createRegistry([aes, cbc, pkcs7, evpKdf, opensslFormat]).use(classicHashesPreset);
  const cipher = registry.createDerivedKeyCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    kdf: {
      name: 'EvpKDF',
      input: 'secret',
      salt: hexToBytes('0001020304050607'),
      hash: 'MD5',
      iterations: 1,
    },
    format: 'OpenSSL',
  });
  const encrypted = cipher.encrypt(textToBytes('abc'));

  const decryptor = cipher.createDecryptor();
  assert.equal(decryptor.process(encrypted.subarray(0, 8)).length, 0);
  assert.equal(decryptor.process(encrypted.subarray(8, 16)).length, 0);
  const plaintext = concatBytes(
    decryptor.process(encrypted.subarray(16, 20)),
    decryptor.finalize(encrypted.subarray(20)),
  );
  assert.equal(bytesToText(plaintext), 'abc');
});

test('derived-key ciphers cover no-format and OpenSSL salt branches', () => {
  const registry = createRegistry([aes, cbc, pkcs7, evpKdf, opensslFormat]).use(classicHashesPreset);
  const cipher = registry.createDerivedKeyCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    kdf: {
      name: 'EvpKDF',
      input: 'secret',
      salt: new Uint8Array(),
    },
  });
  const encrypted = cipher.encrypt(textToBytes('abc'));
  assert.equal(bytesToText(cipher.decrypt(encrypted)), 'abc');

  assert.throws(() => registry.createDerivedKeyCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    kdf: {
      name: 'EvpKDF',
      input: 'secret',
      salt: new Uint8Array(7),
    },
    format: 'OpenSSL',
  }).encrypt(textToBytes('abc')), /salt must be 64 bits/);
});

test('derived-key ciphers cover buffered formats and short OpenSSL decrypt', () => {
  const bufferedFormat = {
    kind: 'format' as const,
    name: 'Buffered',
    stringify({ ciphertext, salt }: { ciphertext: Uint8Array; salt?: Uint8Array }) {
      return concatBytes(new Uint8Array([salt?.length ?? 0]), salt ?? new Uint8Array(), ciphertext);
    },
    parse(input: Uint8Array) {
      const saltLength = input[0];
      return {
        salt: input.slice(1, 1 + saltLength),
        ciphertext: input.slice(1 + saltLength),
      };
    },
  };
  const noSaltFormat = {
    kind: 'format' as const,
    name: 'NoSalt',
    stringify({ ciphertext }: { ciphertext: Uint8Array }) {
      return ciphertext;
    },
    parse(input: Uint8Array) {
      return { ciphertext: input };
    },
  };
  const registry = createRegistry([aes, rc4, cbc, pkcs7, evpKdf, opensslFormat, bufferedFormat, noSaltFormat]).use(classicHashesPreset);
  const cipher = registry.createDerivedKeyCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    kdf: {
      name: 'EvpKDF',
      input: 'secret',
      salt: hexToBytes('0001020304050607'),
    },
    format: { name: 'Buffered' },
  });
  const encryptor = cipher.createEncryptor();
  assert.equal(encryptor.process(textToBytes('a')).length, 0);
  const encrypted = concatBytes(encryptor.process(textToBytes('b')), encryptor.finalize(textToBytes('c')));
  assert.equal(bytesToText(cipher.decrypt(encrypted)), 'abc');

  const decryptor = cipher.createDecryptor();
  assert.equal(decryptor.process(encrypted.subarray(0, 3)).length, 0);
  assert.equal(bytesToText(decryptor.finalize(encrypted.subarray(3))), 'abc');

  const shortOpenSsl = registry.createDerivedKeyCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    kdf: {
      name: 'EvpKDF',
      input: 'secret',
    },
    format: 'OpenSSL',
  });
  assert.throws(() => shortOpenSsl.createDecryptor().finalize(new Uint8Array([1, 2, 3])), /Invalid PKCS#7/);

  const rawCipher = registry.createDerivedKeyCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    kdf: {
      name: 'EvpKDF',
      input: 'secret',
      salt: new Uint8Array(),
    },
  });
  assert.equal(bytesToText(shortOpenSsl.decrypt(rawCipher.encrypt(textToBytes('abc')))), 'abc');

  const streamBufferedCipher = registry.createDerivedKeyCipher({
    cipher: 'RC4',
    kdf: {
      name: 'EvpKDF',
      input: 'secret',
      salt: new Uint8Array(),
    },
    format: { name: 'Buffered' },
    keySize: 16,
  });
  const streamBufferedEncryptor = streamBufferedCipher.createEncryptor();
  assert.equal(streamBufferedEncryptor.process(textToBytes('a')).length, 0);
  assert.equal(bytesToText(streamBufferedCipher.decrypt(streamBufferedEncryptor.finalize(textToBytes('bc')))), 'abc');

  const noSaltCipher = registry.createDerivedKeyCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    kdf: {
      name: 'EvpKDF',
      input: 'secret',
      salt: new Uint8Array(),
    },
    format: { name: 'NoSalt' },
  });
  assert.equal(bytesToText(noSaltCipher.decrypt(noSaltCipher.encrypt(textToBytes('abc')))), 'abc');
});

test('derived-key ciphers validate sizing and invalid kdf outputs', () => {
  const invalidKdf = {
    kind: 'kdf' as const,
    name: 'Invalid',
    derive() {
      return Promise.resolve(new Uint8Array()) as unknown as Uint8Array;
    },
  };
  const noKeySizeCipher = {
    kind: 'cipher' as const,
    name: 'NoKeySize',
    type: 'stream' as const,
    createEncryptor() {
      return identityTransform();
    },
    createDecryptor() {
      return identityTransform();
    },
  };
  const registry = createRegistry([aes, rc4, cbc, pkcs7, evpKdf, invalidKdf, noKeySizeCipher]).use(classicHashesPreset);

  assert.throws(() => registry.createDerivedKeyCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    kdf: {
      name: 'EvpKDF',
      input: 'secret',
      salt: new Uint8Array(),
    },
    keySize: 0,
  }).encrypt(textToBytes('a')), /keySize/);
  assert.throws(() => registry.createDerivedKeyCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    kdf: {
      name: 'EvpKDF',
      input: 'secret',
      salt: new Uint8Array(),
      length: 1,
    },
  }).encrypt(textToBytes('a')), /kdf.length/);
  assert.throws(() => registry.createDerivedKeyCipher({
    cipher: 'NoKeySize',
    kdf: {
      name: 'EvpKDF',
      input: 'secret',
      salt: new Uint8Array(),
    },
  }).encrypt(textToBytes('a')), /requires keySize/);
  assert.throws(() => registry.createDerivedKeyCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    kdf: {
      name: 'Invalid',
      input: 'secret',
      salt: new Uint8Array(),
    },
  }).encrypt(textToBytes('a')), /must return a Uint8Array/);

  const streamCipher = registry.createDerivedKeyCipher({
    cipher: 'RC4',
    kdf: {
      name: 'EvpKDF',
      input: 'secret',
      salt: new Uint8Array(),
    },
    keySize: 16,
  });
  assert.equal(bytesToText(streamCipher.decrypt(streamCipher.encrypt(textToBytes('abc')))), 'abc');
});

function identityTransform() {
  return {
    process(input: Uint8Array) {
      return input;
    },
    finalize(input = new Uint8Array()) {
      return input;
    },
  };
}
