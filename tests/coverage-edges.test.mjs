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
import {
  ansiX923,
  aes,
  cbc,
  cfb,
  ctr,
  des,
  ecb,
  evpKdf,
  gcm,
  iso10126,
  iso97971,
  noPadding,
  ofb,
  opensslFormat,
  pbkdf2,
  pkcs7,
  rc4,
  rc4Drop,
  tripleDes,
  zeroPadding,
  createAesCipher,
  createDesCipher,
  createTripleDesCipher,
  createRc4Transform,
  deriveEvpKdf,
  derivePbkdf2,
} from '@jscrypto/suite';
import { classicHashesPreset, md5, sha256 } from '@jscrypto/hashes';
import { bytesToHex, bytesToText, hexToBytes, textToBytes } from './helpers/bytes.mjs';

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
});

test('classic cipher constructors validate keys and blocks', () => {
  assert.throws(() => createAesCipher(new Uint8Array(15)), /AES key/);
  assert.throws(() => createDesCipher(new Uint8Array(7)), /DES key/);
  assert.throws(() => createTripleDesCipher(new Uint8Array(15)), /Triple DES key/);
  assert.throws(() => createAesCipher(new Uint8Array(16)).encrypt(new Uint8Array(15), new Uint8Array(15)), /multiple of 128 bits/);
  assert.throws(() => createAesCipher(new Uint8Array(16)).decrypt(new Uint8Array(16), new Uint8Array(15)), /output length/);
  assert.throws(() => createAesCipher(new Uint8Array(16)).decrypt(new Uint8Array(16), new Uint8Array(17)), /output length/);
  assert.throws(() => createDesCipher(new Uint8Array(8)).encrypt(new Uint8Array(7), new Uint8Array(7)), /multiple of 64 bits/);
  assert.throws(() => createDesCipher(new Uint8Array(8)).decrypt(new Uint8Array(8), new Uint8Array(7)), /output length/);
  assert.throws(() => createDesCipher(new Uint8Array(8)).decrypt(new Uint8Array(8), new Uint8Array(9)), /output length/);
  assert.throws(() => createTripleDesCipher(new Uint8Array(16)).encrypt(new Uint8Array(7), new Uint8Array(7)), /multiple of 64 bits/);
  assert.throws(() => createTripleDesCipher(new Uint8Array(16)).decrypt(new Uint8Array(8), new Uint8Array(7)), /output length/);
  assert.throws(() => createTripleDesCipher(new Uint8Array(16)).decrypt(new Uint8Array(8), new Uint8Array(9)), /output length/);

});

test('classic kdfs validate inputs and missing registered hashes', () => {
  assert.throws(() => derivePbkdf2({ input: 'x', salt: 's', iterations: 0, length: 16, hash: sha256 }), /PBKDF2 iterations/);
  assert.throws(() => derivePbkdf2({ input: 'x', salt: 's', iterations: 1, length: 0, hash: sha256 }), /PBKDF2 length/);
  assert.throws(() => derivePbkdf2({ input: 'x', iterations: 1, length: 16, hash: sha256 }), /requires salt/);
  assert.throws(() => deriveEvpKdf({ input: 'x', salt: 's', iterations: 0, length: 16, hash: md5 }), /EvpKDF iterations/);
  assert.throws(() => deriveEvpKdf({ input: 'x', salt: 's', length: 0, hash: md5 }), /EvpKDF length/);
  assert.throws(() => deriveEvpKdf({ input: 'x', length: 16, hash: md5 }), /requires salt/);
  assert.equal(derivePbkdf2({
    input: new Uint8Array(65),
    salt: 's',
    iterations: 1,
    length: 16,
    hash: sha256,
  }).length, 16);
  const registry = createRegistry([evpKdf, pbkdf2]);
  assert.throws(() => evpKdf.derive({ input: 'x', salt: 's', length: 16 }, { getHash: registry.getHash.bind(registry) }), /Hash not registered: MD5/);
  assert.throws(() => pbkdf2.derive({ input: 'x', salt: 's', iterations: 1, length: 16 }, { getHash: registry.getHash.bind(registry) }), /Hash not registered: SHA256/);
});

test('classic paddings validate edge cases and random fallbacks', () => {
  assert.throws(() => zeroPadding.pad(textToBytes('a'), 0), /blockSize/);
  assert.deepEqual(zeroPadding.pad(textToBytes('abcd'), 4), textToBytes('abcd'));
  assert.deepEqual(zeroPadding.unpad(new Uint8Array([1, 0, 0])), new Uint8Array([1]));

  assert.throws(() => ansiX923.unpad(new Uint8Array([1, 0]), 2), /ANSI X9.23/);
  assert.throws(() => ansiX923.unpad(new Uint8Array([1, 3]), 2), /ANSI X9.23/);
  assert.throws(() => ansiX923.unpad(new Uint8Array([1, 1, 2, 3]), 4), /ANSI X9.23/);

  assert.throws(() => iso10126.pad(textToBytes('a'), 256), /between 1 and 255/);
  assert.throws(() => iso10126.unpad(new Uint8Array([1, 0]), 2), /ISO 10126/);
  assert.throws(() => iso10126.unpad(new Uint8Array([1, 3]), 2), /ISO 10126/);
  assert.equal(bytesToHex(iso97971.pad(textToBytes('abc'), 4)), '61626380');
  assert.throws(() => pkcs7.unpad(new Uint8Array([1, 3]), 2), /PKCS#7/);
  assert.throws(() => pkcs7.unpad(new Uint8Array([2, 3]), 2), /PKCS#7/);
  assert.throws(() => pkcs7.unpad(new Uint8Array([1, 2]), 2), /PKCS#7/);

  withDeterministicRandom(() => {
    assert.equal(bytesToHex(iso10126.pad(textToBytes('abc'), 4)), '61626301');
    assert.equal(bytesToHex(iso10126.pad(textToBytes('a'), 4)), '61ffff03');
  });
  withNoCryptoRandom(() => {
    assert.equal(bytesToHex(iso10126.pad(textToBytes('a'), 4)), '61ffff03');
  });
});

test('mode finalizers and counter carry branches are covered', () => {
  const blockCipher = {
    blockSize: 2,
    encrypt(input, output) {
      for (let index = 0; index < input.length; index++) {
        output[index] = input[index] ^ 0xff;
      }
      return output;
    },
    decrypt(input, output) {
      for (let index = 0; index < input.length; index++) {
        output[index] = input[index] ^ 0xff;
      }
      return output;
    },
  };

  assert.deepEqual(cbc.createEncryptor({ cipher: blockCipher, iv: new Uint8Array([0, 0]) }).finalize(new Uint8Array([1, 2])), new Uint8Array([254, 253]));
  assert.deepEqual(cbc.createDecryptor({ cipher: blockCipher, iv: new Uint8Array([0, 0]) }).finalize(new Uint8Array([254, 253])), new Uint8Array([1, 2]));
  assert.throws(() => cbc.createEncryptor({ cipher: blockCipher, iv: new Uint8Array([0, 0]) }).process(new Uint8Array([1])), /multiple/);
  assert.deepEqual(ecb.createEncryptor({ cipher: blockCipher }).finalize(new Uint8Array([1, 2])), new Uint8Array([254, 253]));
  assert.deepEqual(ecb.createEncryptor({ cipher: blockCipher }).finalize(), new Uint8Array());
  assert.deepEqual(ecb.createDecryptor({ cipher: blockCipher }).finalize(new Uint8Array([254, 253])), new Uint8Array([1, 2]));
  assert.deepEqual(cfb.createEncryptor({ cipher: blockCipher, iv: new Uint8Array([0, 0]) }).finalize(new Uint8Array([1, 2])), new Uint8Array([254, 253]));
  assert.deepEqual(ofb.createEncryptor({ cipher: blockCipher, iv: new Uint8Array([0, 0]) }).finalize(new Uint8Array([1])), new Uint8Array([254]));
  assert.deepEqual(ctr.createEncryptor({ cipher: blockCipher, iv: new Uint8Array([0, 0]) }).finalize(new Uint8Array([1])), new Uint8Array([254]));

  const observedCounters = [];
  const ctrCipher = {
    blockSize: 2,
    encrypt(input, output) {
      for (let offset = 0; offset < input.length; offset += 2) {
        observedCounters.push(bytesToHex(input.subarray(offset, offset + 2)));
        output[offset] = 0;
        output[offset + 1] = 0;
      }
      return output;
    },
    decrypt(input, output) {
      output.set(input);
      return output;
    },
  };
  ctr.createEncryptor({ cipher: ctrCipher, iv: new Uint8Array([0xff, 0xff]) }).process(new Uint8Array(3));
  assert.deepEqual(observedCounters, ['ffff', '0000']);
  observedCounters.length = 0;
  ctr.createEncryptor({ cipher: ctrCipher, iv: new Uint8Array([0, 0]) }).process(new Uint8Array(1));
  assert.deepEqual(observedCounters, ['0000']);
});

test('RC4 option validation and defaults cover stream branches', () => {
  assert.equal(bytesToHex(createRc4Transform(textToBytes('secret')).finalize()), '');
  const direct = createRc4Transform(textToBytes('secret'));
  direct.finalize(textToBytes('a'));
  assert.throws(() => direct.process(textToBytes('b')), /already finalized/);
  assert.throws(() => createRc4Transform(textToBytes('secret'), -1), /non-negative/);

  const registry = createRegistry([rc4, rc4Drop]);
  assert.equal(registry.createCipher({ cipher: 'RC4', key: textToBytes('secret') }).encrypt(textToBytes('x')).length, 1);
  assert.equal(registry.createCipher({ cipher: 'RC4Drop', key: textToBytes('secret') }).decrypt(textToBytes('x')).length, 1);
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
    kind: 'format',
    name: 'Buffered',
    stringify({ ciphertext, salt }) {
      return concatBytes(new Uint8Array([salt?.length ?? 0]), salt ?? new Uint8Array(), ciphertext);
    },
    parse(input) {
      const saltLength = input[0];
      return {
        salt: input.slice(1, 1 + saltLength),
        ciphertext: input.slice(1 + saltLength),
      };
    },
  };
  const noSaltFormat = {
    kind: 'format',
    name: 'NoSalt',
    stringify({ ciphertext }) {
      return ciphertext;
    },
    parse(input) {
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
    kind: 'kdf',
    name: 'Invalid',
    derive() {
      return Promise.resolve(new Uint8Array());
    },
  };
  const noKeySizeCipher = {
    kind: 'cipher',
    name: 'NoKeySize',
    type: 'stream',
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
    process(input) {
      return input;
    },
    finalize(input = new Uint8Array()) {
      return input;
    },
  };
}

function withDeterministicRandom(callback) {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
  const originalRandom = Math.random;
  Object.defineProperty(globalThis, 'crypto', {
    configurable: true,
    value: {
      getRandomValues(array) {
        return array;
      },
    },
  });
  Math.random = () => 0.999;
  try {
    callback();
  } finally {
    Math.random = originalRandom;
    if (descriptor) {
      Object.defineProperty(globalThis, 'crypto', descriptor);
    } else {
      delete globalThis.crypto;
    }
  }
}

function withNoCryptoRandom(callback) {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
  const originalRandom = Math.random;
  delete globalThis.crypto;
  Math.random = () => 0.999;
  try {
    callback();
  } finally {
    Math.random = originalRandom;
    if (descriptor) {
      Object.defineProperty(globalThis, 'crypto', descriptor);
    }
  }
}
