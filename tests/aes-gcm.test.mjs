import assert from 'node:assert/strict';
import { test } from 'node:test';
import { concatBytes, createRegistry } from '@jscrypto/core';
import { aes, aesGcm, createAesCipher, gcm } from '@jscrypto/suite';
import { bytesToHex, bytesToText, hexToBytes, textToBytes } from './helpers/bytes.mjs';

function createAesGcmRegistry() {
  return createRegistry()
    .use(aes)
    .use(gcm);
}

function createAesGcmAeadRegistry() {
  return createRegistry()
    .use(aes)
    .use(gcm)
    .use(aesGcm);
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

test('AES-GCM can mutate input buffers for full blocks', () => {
  const registry = createAesGcmRegistry();
  const key = hexToBytes('000102030405060708090a0b0c0d0e0f');
  const nonce = hexToBytes('101112131415161718191a1b');
  const plaintext = textToBytes('0123456789abcdef0123456789abcdef');
  const expectedPlaintext = plaintext.slice();
  const encryptor = registry.createEncryptor({ cipher: 'AES', mode: 'GCM', key, nonce, mutableInput: true });

  const ciphertext = encryptor.process(plaintext);
  assert.equal(ciphertext.buffer, plaintext.buffer);
  assert.notDeepEqual(plaintext, expectedPlaintext);

  const sealed = concatBytes(ciphertext, encryptor.finalize());
  const decrypted = registry.decrypt({ cipher: 'AES', mode: 'GCM', key, nonce, ciphertext: sealed });
  assert.deepEqual(decrypted, expectedPlaintext);

  const sealedCopy = sealed.slice();
  const decryptor = gcm.createDecryptor({ cipher: createAesCipher(key), iv: nonce, options: { mutableInput: true } });
  const mutablePlaintext = decryptor.finalize(sealedCopy);
  assert.equal(mutablePlaintext.buffer, sealedCopy.buffer);
  assert.deepEqual(mutablePlaintext, expectedPlaintext);
});

test('AES-GCM streams with mutable input after a pending partial chunk', () => {
  const registry = createAesGcmRegistry();
  const key = hexToBytes('000102030405060708090a0b0c0d0e0f');
  const nonce = hexToBytes('101112131415161718191a1b');
  const plaintext = textToBytes('pending block then full block data');
  const expected = registry.encrypt({ cipher: 'AES', mode: 'GCM', key, nonce, plaintext });
  const encryptor = registry.createEncryptor({ cipher: 'AES', mode: 'GCM', key, nonce, mutableInput: true });

  const ciphertext = concatBytes(
    encryptor.process(plaintext.subarray(0, 7)),
    encryptor.process(plaintext.subarray(7, 29)),
    encryptor.finalize(plaintext.subarray(29)),
  );

  assert.deepEqual(ciphertext, expected);
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
    encrypt(input, output) {
      output.set(input);
      return output;
    },
    decrypt(input, output) {
      output.set(input);
      return output;
    },
  };

  assert.throws(() => gcm.createEncryptor({ cipher: blockCipher, iv: new Uint8Array(12) }), /128-bit block cipher/);
});

// --- createAead({ algorithm: 'AES-GCM' }) ---

test('component metadata matches the public surface', () => {
  assert.equal(aesGcm.kind, 'aead');
  assert.equal(aesGcm.name, 'AES-GCM');
  assert.deepEqual(aesGcm.keySizes, [16, 24, 32]);
  assert.equal(aesGcm.recommendedNonceSize, 12);
  assert.deepEqual(
    aesGcm.tagSizes,
    [4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
  );
  assert.equal(typeof aesGcm.create, 'function');
});

test('createAead AES-128-GCM matches empty NIST vector', () => {
  const registry = createAesGcmAeadRegistry();
  const aead = registry.createAead({
    algorithm: 'AES-GCM',
    key: hexToBytes('00000000000000000000000000000000'),
  });
  const sealed = aead.seal(new Uint8Array(), { nonce: hexToBytes('000000000000000000000000') });

  assert.equal(bytesToHex(sealed), '58e2fccefa7e3061367f1d57a4e7455a');
  assert.deepEqual(
    aead.open(sealed, { nonce: hexToBytes('000000000000000000000000') }),
    new Uint8Array(),
  );
});

test('createAead AES-128-GCM matches NIST one-block vector', () => {
  const registry = createAesGcmAeadRegistry();
  const aead = registry.createAead({
    algorithm: 'AES-GCM',
    key: hexToBytes('00000000000000000000000000000000'),
  });
  const sealed = aead.seal(hexToBytes('00000000000000000000000000000000'), {
    nonce: hexToBytes('000000000000000000000000'),
  });

  assert.equal(bytesToHex(sealed), '0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf');
});

test('createAead AES-128-GCM authenticates AAD with NIST vector', () => {
  const registry = createAesGcmAeadRegistry();
  const key = hexToBytes('feffe9928665731c6d6a8f9467308308');
  const nonce = hexToBytes('cafebabefacedbaddecaf888');
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

  const aead = registry.createAead({ algorithm: 'AES-GCM', key });
  const sealed = aead.seal(plaintext, { nonce, aad });
  assert.equal(bytesToHex(sealed), expected);
  assert.deepEqual(aead.open(sealed, { nonce, aad }), plaintext);
});

test('createAead AES-GCM supports appended and detached tags with shorter tag lengths', () => {
  const registry = createAesGcmAeadRegistry();
  const key = hexToBytes('000102030405060708090a0b0c0d0e0f');
  const nonce = hexToBytes('101112131415161718191a1b');
  const plaintext = textToBytes('detached tag');

  const aead = registry.createAead({ algorithm: 'AES-GCM', key });
  const sealed = aead.seal(plaintext, { nonce, tagLength: 12 });
  const ciphertext = sealed.subarray(0, sealed.length - 12);
  const tag = sealed.subarray(sealed.length - 12);
  assert.equal(tag.length, 12);

  assert.equal(bytesToText(aead.open(sealed, { nonce, tagLength: 12 })), 'detached tag');
  assert.equal(bytesToText(aead.open(ciphertext, { nonce, tag })), 'detached tag');
});

test('createAead AES-GCM supports primitive streaming seal/open', () => {
  const registry = createAesGcmAeadRegistry();
  const key = hexToBytes('000102030405060708090a0b0c0d0e0f');
  const nonce = hexToBytes('101112131415161718191a1b');
  const aad = textToBytes('metadata');
  const plaintext = textToBytes('streaming AEAD primitive encrypts chunks and verifies before opening');
  const aead = registry.createAead({ algorithm: 'AES-GCM', key });
  const expected = aead.seal(plaintext, { nonce, aad, tagLength: 12 });

  const sealer = aead.createSealer({ nonce, aad, tagLength: 12 });
  const sealed = concatBytes(
    sealer.process(plaintext.subarray(0, 3)),
    sealer.process(plaintext.subarray(3, 29)),
    sealer.finalize(plaintext.subarray(29)),
  );
  assert.equal(bytesToHex(sealed), bytesToHex(expected));

  const opener = aead.createOpener({ nonce, aad, tagLength: 12 });
  assert.deepEqual(opener.process(sealed.subarray(0, 5)), new Uint8Array(0));
  assert.deepEqual(opener.process(sealed.subarray(5, 41)), new Uint8Array(0));
  assert.deepEqual(opener.finalize(sealed.subarray(41)), plaintext);
});

test('createAead AES-GCM throws AES-GCM authentication failed for a wrong tag', () => {
  const registry = createAesGcmAeadRegistry();
  const key = hexToBytes('000102030405060708090a0b0c0d0e0f');
  const nonce = hexToBytes('101112131415161718191a1b');
  const aead = registry.createAead({ algorithm: 'AES-GCM', key });
  const sealed = aead.seal(textToBytes('abc'), { nonce });
  const corrupted = sealed.slice();
  corrupted[0] ^= 1;

  assert.throws(() => aead.open(corrupted, { nonce }), /AES-GCM authentication failed/);
});

test('createAead AES-GCM requires a nonce', () => {
  const registry = createAesGcmAeadRegistry();
  const aead = registry.createAead({
    algorithm: 'AES-GCM',
    key: hexToBytes('000102030405060708090a0b0c0d0e0f'),
  });

  assert.throws(() => aead.seal(textToBytes('abc'), {}), /AES-GCM requires a nonce/);
  assert.throws(() => aead.open(textToBytes('abc'), {}), /AES-GCM requires a nonce/);
});

test('createAead AES-GCM ignores a padding extra field instead of throwing', () => {
  const registry = createAesGcmAeadRegistry();
  const key = hexToBytes('000102030405060708090a0b0c0d0e0f');
  const nonce = hexToBytes('101112131415161718191a1b');
  const plaintext = textToBytes('padding has no effect');

  // Extra fields such as `padding` are documented as no-ops on the AEAD path
  // and must not throw by themselves when supplied at creation or operation time.
  const aead = registry.createAead({ algorithm: 'AES-GCM', key, padding: 'Pkcs7' });
  const sealed = aead.seal(plaintext, { nonce, padding: 'Pkcs7', mode: 'CBC' });
  assert.equal(
    bytesToText(aead.open(sealed, { nonce, padding: 'Pkcs7' })),
    'padding has no effect',
  );
});

test('createAead AES-GCM prefers detached tag length over tagLength', () => {
  const registry = createAesGcmAeadRegistry();
  const key = hexToBytes('000102030405060708090a0b0c0d0e0f');
  const nonce = hexToBytes('101112131415161718191a1b');
  const plaintext = textToBytes('tag wins');
  const aead = registry.createAead({ algorithm: 'AES-GCM', key });
  const sealed = aead.seal(plaintext, { nonce, tagLength: 12 });
  const ciphertext = sealed.subarray(0, sealed.length - 12);
  const tag = sealed.subarray(sealed.length - 12);

  // tagLength mismatches are ignored when a detached tag is provided.
  assert.equal(
    bytesToText(aead.open(ciphertext, { nonce, tag, tagLength: 16 })),
    'tag wins',
  );
});

test('createAead AES-GCM supports OpenSSL-unsupported tag lengths such as 5', () => {
  const registry = createAesGcmAeadRegistry();
  const key = hexToBytes('000102030405060708090a0b0c0d0e0f');
  const nonce = hexToBytes('101112131415161718191a1b');
  const plaintext = textToBytes('tag length five');
  const aead = registry.createAead({ algorithm: 'AES-GCM', key });

  // Node/OpenSSL rejects authTagLength 5/6/7/9/10/11; the Node AEAD build must
  // still accept these via the JS compatibility fallback.
  const sealed = aead.seal(plaintext, { nonce, tagLength: 5 });
  assert.equal(sealed.length, plaintext.length + 5);
  assert.equal(bytesToText(aead.open(sealed, { nonce, tagLength: 5 })), 'tag length five');

  const ciphertext = sealed.subarray(0, sealed.length - 5);
  const tag = sealed.subarray(sealed.length - 5);
  assert.equal(
    bytesToText(aead.open(ciphertext, { nonce, tag, tagLength: 16 })),
    'tag length five',
  );
});

test('createAead AES-GCM supports an 8-byte nonce and 12-byte tag via the fast path', () => {
  const registry = createAesGcmAeadRegistry();
  const key = hexToBytes('000102030405060708090a0b0c0d0e0f');
  const nonce = hexToBytes('1011121314151617');
  const plaintext = textToBytes('fast path nonce and tag');

  const aead = registry.createAead({ algorithm: 'AES-GCM', key });
  const sealed = aead.seal(plaintext, { nonce, tagLength: 12 });
  assert.equal(sealed.length, plaintext.length + 12);
  assert.equal(bytesToText(aead.open(sealed, { nonce, tagLength: 12 })), 'fast path nonce and tag');
});

test('createAead AES-GCM falls back to the compatibility path for short (<8 byte) nonces', () => {
  const registry = createAesGcmAeadRegistry();
  const key = hexToBytes('000102030405060708090a0b0c0d0e0f');
  const nonce = hexToBytes('101112131415');
  const plaintext = textToBytes('short nonce fallback');

  const aead = registry.createAead({ algorithm: 'AES-GCM', key });
  const sealed = aead.seal(plaintext, { nonce });
  assert.equal(bytesToText(aead.open(sealed, { nonce })), 'short nonce fallback');

  // The fallback path must match the existing compatibility mode output.
  const modeCiphertext = createAesGcmRegistry().encrypt({
    cipher: 'AES',
    mode: 'GCM',
    key,
    nonce,
    plaintext,
  });
  assert.equal(bytesToHex(sealed), bytesToHex(modeCiphertext));
});

test('compatibility createCipher AES+GCM still works and ignores padding', () => {
  const registry = createAesGcmRegistry();
  const key = hexToBytes('000102030405060708090a0b0c0d0e0f');
  const iv = hexToBytes('101112131415161718191a1b');
  const plaintext = textToBytes('compatibility path');

  const ciphertext = registry.encrypt({ cipher: 'AES', mode: 'GCM', key, iv, plaintext, padding: 'Pkcs7' });
  assert.equal(
    bytesToText(registry.decrypt({ cipher: 'AES', mode: 'GCM', key, iv, ciphertext, padding: 'Pkcs7' })),
    'compatibility path',
  );
});
