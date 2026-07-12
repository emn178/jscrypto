import assert from 'node:assert/strict';
import { test } from 'node:test';
import { concatBytes, createRegistry } from '@jscrypto/core';
import { aes, createAesCipher, gcm } from '@jscrypto/classic';
import { bytesToHex, bytesToText, hexToBytes, textToBytes } from './helpers/bytes.mjs';

function createAesGcmRegistry() {
  return createRegistry()
    .use(aes)
    .use(gcm);
}

test('AES-128-GCM encrypts and decrypts empty NIST vector', () => {
  const registry = createAesGcmRegistry();
  const output = registry.encrypt({
    cipher: 'AES',
    mode: 'GCM',
    key: hexToBytes('00000000000000000000000000000000'),
    iv: hexToBytes('000000000000000000000000'),
    plaintext: new Uint8Array(),
  });

  assert.equal(bytesToHex(output), '58e2fccefa7e3061367f1d57a4e7455a');
  assert.deepEqual(registry.decrypt({
    cipher: 'AES',
    mode: 'GCM',
    key: hexToBytes('00000000000000000000000000000000'),
    iv: hexToBytes('000000000000000000000000'),
    ciphertext: output,
  }), new Uint8Array());
});

test('AES-128-GCM encrypts NIST one-block vector', () => {
  const output = createAesGcmRegistry().encrypt({
    cipher: 'AES',
    mode: 'GCM',
    key: hexToBytes('00000000000000000000000000000000'),
    iv: hexToBytes('000000000000000000000000'),
    plaintext: hexToBytes('00000000000000000000000000000000'),
  });

  assert.equal(bytesToHex(output), '0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf');
});

test('AES-128-GCM authenticates AAD with NIST vector', () => {
  const registry = createAesGcmRegistry();
  const key = hexToBytes('feffe9928665731c6d6a8f9467308308');
  const iv = hexToBytes('cafebabefacedbaddecaf888');
  const aad = hexToBytes('feedfacedeadbeeffeedfacedeadbeefabaddad2');
  const plaintext = hexToBytes(
    'd9313225f88406e5a55909c5aff5269a' +
    '86a7a9531534f7da2e4c303d8a318a72' +
    '1c3c0c95956809532fcf0e2449a6b525' +
    'b16aedf5aa0de657ba637b391aafd255',
  );
  const expected = (
    '42831ec2217774244b7221b784d0d49c' +
    'e3aa212f2c02a4e035c17e2329aca12e' +
    '21d514b25466931c7d8f6a5aac84aa05' +
    '1ba30b396a0aac973d58e091' +
    '473f5985da80ce830cfda02da2a218a1744f4c76'
  );

  const ciphertext = registry.encrypt({ cipher: 'AES', mode: 'GCM', key, iv, aad, plaintext });
  assert.equal(bytesToHex(ciphertext), expected);
  assert.deepEqual(registry.decrypt({ cipher: 'AES', mode: 'GCM', key, iv, aad, ciphertext }), plaintext);
});

test('AES-GCM streams encryption and verifies before releasing plaintext', () => {
  const registry = createAesGcmRegistry();
  const key = hexToBytes('000102030405060708090a0b0c0d0e0f');
  const nonce = hexToBytes('101112131415161718191a1b');
  const plaintext = textToBytes('hello gcm streaming');
  const encryptor = registry.createEncryptor({ cipher: 'AES', mode: 'GCM', key, nonce, aad: textToBytes('aad') });

  const ciphertext = concatBytes(
    encryptor.process(plaintext.subarray(0, 5)),
    encryptor.process(plaintext.subarray(5, 9)),
    encryptor.finalize(plaintext.subarray(9)),
  );

  const decryptor = registry.createDecryptor({ cipher: 'AES', mode: 'GCM', key, nonce, aad: textToBytes('aad') });
  assert.deepEqual(decryptor.process(ciphertext.subarray(0, 4)), new Uint8Array());
  assert.deepEqual(decryptor.process(ciphertext.subarray(4, 11)), new Uint8Array());
  assert.equal(bytesToText(decryptor.finalize(ciphertext.subarray(11))), 'hello gcm streaming');
});

test('AES-GCM supports detached tags and shorter tag lengths', () => {
  const registry = createAesGcmRegistry();
  const key = hexToBytes('000102030405060708090a0b0c0d0e0f');
  const iv = hexToBytes('101112131415161718191a1b');
  const plaintext = textToBytes('detached tag');
  const sealed = registry.encrypt({ cipher: 'AES', mode: 'GCM', key, iv, plaintext, tagLength: 12 });
  const ciphertext = sealed.subarray(0, sealed.length - 12);
  const tag = sealed.subarray(sealed.length - 12);

  assert.equal(tag.length, 12);
  assert.equal(bytesToText(registry.decrypt({ cipher: 'AES', mode: 'GCM', key, iv, tag, ciphertext })), 'detached tag');
});

test('AES-GCM decryptor accepts ciphertext passed to finalize', () => {
  const registry = createAesGcmRegistry();
  const key = hexToBytes('000102030405060708090a0b0c0d0e0f');
  const iv = hexToBytes('101112131415161718191a1b');
  const ciphertext = registry.encrypt({ cipher: 'AES', mode: 'GCM', key, iv, plaintext: textToBytes('finalize input') });
  const decryptor = gcm.createDecryptor({ cipher: createAesCipher(key), iv });

  assert.equal(bytesToText(decryptor.finalize(ciphertext)), 'finalize input');
});

test('AES-GCM direct encryptor can finalize without pending input', () => {
  const key = hexToBytes('00000000000000000000000000000000');
  const iv = hexToBytes('000000000000000000000000');
  const encryptor = gcm.createEncryptor({ cipher: createAesCipher(key), iv });

  assert.equal(bytesToHex(encryptor.finalize()), '58e2fccefa7e3061367f1d57a4e7455a');
});

test('AES-GCM direct encryptor accepts plaintext passed to finalize', () => {
  const key = hexToBytes('00000000000000000000000000000000');
  const iv = hexToBytes('000000000000000000000000');
  const encryptor = gcm.createEncryptor({ cipher: createAesCipher(key), iv });

  assert.equal(
    bytesToHex(encryptor.finalize(hexToBytes('00000000000000000000000000000000'))),
    '0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf',
  );
});

test('AES-GCM supports non-96-bit nonce via GHASH-derived initial counter', () => {
  const registry = createAesGcmRegistry();
  const key = hexToBytes('000102030405060708090a0b0c0d0e0f');
  const nonce = hexToBytes('1011121314151617');
  const plaintext = textToBytes('short nonce');
  const ciphertext = registry.encrypt({ cipher: 'AES', mode: 'GCM', key, nonce, plaintext });

  assert.equal(bytesToText(registry.decrypt({ cipher: 'AES', mode: 'GCM', key, nonce, ciphertext })), 'short nonce');
});

test('AES-GCM rejects invalid options and authentication failures', () => {
  const registry = createAesGcmRegistry();
  const key = hexToBytes('000102030405060708090a0b0c0d0e0f');
  const iv = hexToBytes('101112131415161718191a1b');
  const ciphertext = registry.encrypt({ cipher: 'AES', mode: 'GCM', key, iv, plaintext: textToBytes('abc') });
  const corrupted = ciphertext.slice();
  corrupted[0] ^= 1;

  assert.throws(() => registry.createEncryptor({ cipher: 'AES', mode: 'GCM', key }), /IV\/nonce/);
  assert.throws(() => registry.createEncryptor({ cipher: 'AES', mode: 'GCM', key, iv: new Uint8Array() }), /requires a nonce/);
  assert.throws(() => registry.createEncryptor({ cipher: 'AES', mode: 'GCM', key, iv, nonce: iv }), /either iv or nonce/);
  assert.throws(() => registry.createEncryptor({ cipher: 'AES', mode: 'GCM', key, iv, aad: [] }), /Uint8Array/);
  assert.throws(() => registry.createDecryptor({ cipher: 'AES', mode: 'GCM', key, iv, tag: [] }), /Uint8Array/);
  assert.throws(() => registry.createEncryptor({ cipher: 'AES', mode: 'GCM', key, iv, tagLength: 3 }), /tagLength/);
  assert.throws(() => registry.decrypt({ cipher: 'AES', mode: 'GCM', key, iv, ciphertext: new Uint8Array(3) }), /authentication tag/);
  assert.throws(() => registry.decrypt({ cipher: 'AES', mode: 'GCM', key, iv, ciphertext: corrupted }), /authentication failed/);
});

test('GCM requires a 128-bit block cipher', () => {
  const blockCipher = {
    blockSize: 8,
    encryptBlock(block) {
      return block;
    },
    decryptBlock(block) {
      return block;
    },
  };

  assert.throws(() => gcm.createEncryptor({ cipher: blockCipher, iv: new Uint8Array(12) }), /128-bit block cipher/);
});
