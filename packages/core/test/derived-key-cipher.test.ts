import assert from 'node:assert/strict';
import { test } from 'node:test';
import { concatBytes } from '@jscrypto/core';
import { classicHashesPreset } from '@jscrypto/hashes';
import { createClassicRegistry, registry } from './helpers/classic-registry.js';
import { bytesToHex, bytesToText, hexToBytes, textToBytes } from './helpers/bytes.js';

registry.use(classicHashesPreset);

test('registry.derive supports PBKDF2 and EvpKDF with input', () => {
  const pbkdf2 = registry.derive({
    name: 'PBKDF2',
    input: 'password',
    salt: 'ATHENA.MIT.EDUraeburn',
    iterations: 2,
    length: 32,
    hash: 'SHA256',
  });
  assert.equal(
    bytesToHex(pbkdf2),
    '262fb72ea65b44ab5ceba7f8c8bfa7815ff9939204eb7357a59a75877d745777',
  );

  const evp = registry.derive({
    name: 'EvpKDF',
    input: 'password',
    salt: 'saltsalt',
    length: 48,
    hash: 'MD5',
  });
  assert.equal(
    bytesToHex(evp),
    'fdbdf3419fff98bdb0241390f62a9db35f4aba29d77566377997314ebfc709f20b5ca7b1081f94b1ac12e3c8ba87d05a',
  );
});

test('registry.derive resolves hashes and missing components', () => {
  assert.throws(() => registry.derive({
    name: 'PBKDF2',
    input: 'secret',
    salt: 'salt',
    iterations: 1,
    length: 16,
    hash: 'MISSING',
  }), /Hash not registered: MISSING/);

  assert.throws(() => registry.derive({
    name: 'MissingKdf',
    input: 'secret',
    salt: 'salt',
    length: 16,
  }), {
    name: 'MissingComponentError',
    message: 'Component not found: kdf:MissingKdf',
  });
});

test('createDerivedKeyCipher accepts OpenSSL format with explicit salt', () => {
  const salt = hexToBytes('0001020304050607');
  const cipher = registry.createDerivedKeyCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    kdf: {
      name: 'EvpKDF',
      input: 'secret',
      hash: 'MD5',
      iterations: 1,
      salt,
    },
    format: 'OpenSSL',
  });
  const encrypted = cipher.encrypt(textToBytes('abc'));
  assert.equal(bytesToHex(encrypted.subarray(0, 8)), '53616c7465645f5f');
  assert.equal(bytesToText(cipher.decrypt(encrypted)), 'abc');

  const operationSaltCipher = registry.createDerivedKeyCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    kdf: {
      name: 'EvpKDF',
      input: 'secret',
      hash: 'MD5',
      iterations: 1,
    },
    format: 'OpenSSL',
  });
  const operationEncrypted = operationSaltCipher.encrypt(textToBytes('abc'), { salt });
  assert.equal(bytesToHex(operationEncrypted.subarray(0, 16)), '53616c7465645f5f0001020304050607');
  assert.equal(bytesToText(operationSaltCipher.decrypt(operationEncrypted)), 'abc');
});

test('createDerivedKeyCipher requires salt for OpenSSL format encrypt', () => {
  assert.throws(() => registry.createDerivedKeyCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    kdf: {
      name: 'EvpKDF',
      input: 'secret',
      hash: 'MD5',
      iterations: 1,
    },
    format: 'OpenSSL',
  }).encrypt(textToBytes('abc')), /requires salt/);
});

test('createDerivedKeyCipher operation salt overrides kdf.salt', () => {
  const creationSalt = hexToBytes('0001020304050607');
  const operationSalt = hexToBytes('0102030405060708');
  const cipher = registry.createDerivedKeyCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    kdf: {
      name: 'EvpKDF',
      input: 'secret',
      hash: 'MD5',
      iterations: 1,
      salt: creationSalt,
    },
    format: 'OpenSSL',
  });

  const encrypted = cipher.encrypt(textToBytes('abc'), { salt: operationSalt });
  assert.equal(bytesToHex(encrypted.subarray(8, 16)), bytesToHex(operationSalt));
  assert.notEqual(bytesToHex(encrypted.subarray(8, 16)), bytesToHex(creationSalt));
});

test('createDerivedKeyCipher OpenSSL decrypt prefers parsed salt over operation salt', () => {
  const parsedSalt = hexToBytes('0001020304050607');
  const operationSalt = hexToBytes('ffffffffffffffff');
  const cipher = registry.createDerivedKeyCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    kdf: {
      name: 'EvpKDF',
      input: 'secret',
      hash: 'MD5',
      iterations: 1,
    },
    format: 'OpenSSL',
  });
  const encrypted = cipher.encrypt(textToBytes('abc'), { salt: parsedSalt });
  assert.equal(bytesToText(cipher.decrypt(encrypted, { salt: operationSalt })), 'abc');
});

test('createDerivedKeyCipher decrypt mirrors encrypt without separate iv', () => {
  const salt = hexToBytes('0001020304050607');
  const cipher = registry.createDerivedKeyCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    kdf: {
      name: 'PBKDF2',
      input: 'secret',
      hash: 'SHA256',
      iterations: 1000,
    },
    keySize: 32,
  });
  const encrypted = cipher.encrypt(textToBytes('hello'), { salt });
  assert.equal(bytesToText(cipher.decrypt(encrypted, { salt })), 'hello');
});

test('createDerivedKeyCipher GCM derives key only and requires operation nonce', () => {
  const salt = hexToBytes('0102030405060708');
  const nonce = hexToBytes('000000000000000000000000');
  const cipher = registry.createDerivedKeyCipher({
    cipher: 'AES',
    mode: 'GCM',
    kdf: {
      name: 'PBKDF2',
      input: 'secret',
      hash: 'SHA256',
      iterations: 1000,
    },
    keySize: 16,
  });

  assert.throws(() => cipher.encrypt(textToBytes('abc'), { salt }), /requires/);
  const sealed = cipher.encrypt(textToBytes('abc'), { salt, nonce, tagLength: 16 });
  assert.ok(sealed.length > 16);
  assert.equal(bytesToText(cipher.decrypt(sealed, { salt, nonce })), 'abc');
});

test('createDerivedKeyAead derives keys and requires operation nonce', () => {
  const salt = hexToBytes('0102030405060708');
  const nonce = hexToBytes('000000000000000000000000');
  const aead = registry.createDerivedKeyAead({
    algorithm: 'AES-GCM',
    kdf: {
      name: 'PBKDF2',
      input: 'secret',
      hash: 'SHA256',
      iterations: 1000,
    },
    keySize: 16,
  });

  assert.throws(() => aead.seal(textToBytes('abc'), { salt }), /requires a nonce/);
  const { seal, open } = aead;
  const sealed = seal(textToBytes('abc'), { salt, nonce, tagLength: 16 });
  assert.ok(sealed.length > 16);
  assert.equal(bytesToText(open(sealed, { salt, nonce })), 'abc');

  const tag = sealed.slice(sealed.length - 16);
  const ciphertext = sealed.slice(0, sealed.length - 16);
  assert.equal(bytesToText(aead.open(ciphertext, { salt, nonce, tag })), 'abc');
});

test('createDerivedKeyAead derives default key size from AEAD metadata', () => {
  const salt = hexToBytes('0102030405060708');
  const nonce = hexToBytes('000000000000000000000000');
  const aead = registry.createDerivedKeyAead({
    algorithm: 'AES-GCM',
    kdf: {
      name: 'PBKDF2',
      input: 'secret',
      salt,
      hash: 'SHA256',
      iterations: 1000,
    },
    nonce,
  });

  const sealed = aead.seal(textToBytes('abc'));
  assert.equal(bytesToText(aead.open(sealed)), 'abc');
});

test('createDerivedKeyAead supports OpenSSL format and parsed salt', () => {
  const salt = hexToBytes('0001020304050607');
  const nonce = hexToBytes('000000000000000000000000');
  const aead = registry.createDerivedKeyAead({
    algorithm: 'AES-GCM',
    kdf: {
      name: 'EvpKDF',
      input: 'secret',
      hash: 'MD5',
      iterations: 1,
    },
    format: 'OpenSSL',
    keySize: 16,
  });

  const sealed = aead.seal(textToBytes('abc'), { salt, nonce });
  assert.equal(bytesToHex(sealed.subarray(0, 16)), '53616c7465645f5f0001020304050607');
  assert.equal(bytesToText(aead.open(sealed, { salt: hexToBytes('ffffffffffffffff'), nonce })), 'abc');

  const sealer = aead.createSealer({ salt, nonce });
  const part1 = sealer.process(textToBytes('a'));
  const part2 = sealer.process(textToBytes('b'));
  const part3 = sealer.finalize(textToBytes('c'));
  assert.equal(bytesToHex(part1.subarray(0, 16)), '53616c7465645f5f0001020304050607');
  const streamingSealed = concatBytes(part1, part2, part3);
  assert.equal(bytesToText(aead.open(streamingSealed, { nonce })), 'abc');
});

test('createDerivedKeyAead streams OpenSSL decryption input', () => {
  const salt = hexToBytes('0001020304050607');
  const nonce = hexToBytes('000000000000000000000000');
  const raw = registry.createDerivedKeyAead({
    algorithm: 'AES-GCM',
    kdf: {
      name: 'EvpKDF',
      input: 'secret',
      hash: 'MD5',
      iterations: 1,
      salt,
    },
    keySize: 16,
  });
  const rawSealed = raw.seal(textToBytes('abc'), { nonce });

  const formatted = registry.createDerivedKeyAead({
    algorithm: 'AES-GCM',
    kdf: {
      name: 'EvpKDF',
      input: 'secret',
      hash: 'MD5',
      iterations: 1,
    },
    format: 'OpenSSL',
    keySize: 16,
  });
  const opener = formatted.createOpener({ nonce, salt });
  const plaintext = concatBytes(
    opener.process(rawSealed.subarray(0, 4)),
    opener.process(rawSealed.subarray(4)),
    opener.finalize(),
  );
  assert.equal(bytesToText(plaintext), 'abc');

  assert.throws(() => formatted.createOpener({ nonce, salt }).finalize(rawSealed.subarray(0, 4)));
});

test('createDerivedKeyAead buffers non-streaming format output and input', () => {
  const salt = hexToBytes('0001020304050607');
  const nonce = hexToBytes('000000000000000000000000');
  const plaintext = textToBytes('abcdefghijklmnopq');
  const bufferedFormat = {
    kind: 'format' as const,
    name: 'AeadBuffered',
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
    name: 'AeadNoSalt',
    stringify({ ciphertext }: { ciphertext: Uint8Array }) {
      return ciphertext;
    },
    parse(input: Uint8Array) {
      return {
        ciphertext: input,
      };
    },
  };
  const localRegistry = createClassicRegistry()
    .use(classicHashesPreset)
    .use(bufferedFormat)
    .use(noSaltFormat);
  const aead = localRegistry.createDerivedKeyAead({
    algorithm: 'AES-GCM',
    kdf: {
      name: 'PBKDF2',
      input: 'secret',
      hash: 'SHA256',
      iterations: 1000,
    },
    format: 'AeadBuffered',
    keySize: 16,
  });

  const sealer = aead.createSealer({ salt, nonce });
  assert.equal(sealer.process(plaintext.subarray(0, 16)).length, 0);
  const sealed = sealer.finalize(plaintext.subarray(16));
  assert.equal(sealed[0], 8);
  assert.equal(bytesToHex(sealed.subarray(1, 9)), bytesToHex(salt));

  const opener = aead.createOpener({ nonce });
  assert.equal(opener.process(sealed.subarray(0, 5)).length, 0);
  assert.equal(opener.process(sealed.subarray(5)).length, 0);
  assert.equal(bytesToText(opener.finalize()), bytesToText(plaintext));
  assert.equal(bytesToText(aead.createOpener({ nonce }).finalize(sealed)), bytesToText(plaintext));

  const noSaltAead = localRegistry.createDerivedKeyAead({
    algorithm: 'AES-GCM',
    kdf: {
      name: 'PBKDF2',
      input: 'secret',
      hash: 'SHA256',
      iterations: 1000,
    },
    format: 'AeadNoSalt',
    keySize: 16,
  });
  const noSaltSealed = noSaltAead.seal(plaintext, { salt, nonce });
  assert.equal(bytesToText(noSaltAead.open(noSaltSealed, { salt, nonce })), bytesToText(plaintext));
});

test('createDerivedKeyAead rejects invalid options and length conflicts', () => {
  assert.throws(() => registry.createDerivedKeyAead({
    algorithm: 'AES-GCM',
    kdf: 'PBKDF2' as never,
  }), /createDerivedKeyAead requires kdf to be an object/);

  assert.throws(() => registry.createDerivedKeyAead({
    algorithm: 'AES-GCM',
    kdf: {
      name: 'PBKDF2',
      input: 'secret',
      hash: 'SHA256',
      iterations: 1000,
      length: 32,
    },
    keySize: 16,
  }).seal(textToBytes('abc'), {
    salt: hexToBytes('0102030405060708'),
    nonce: hexToBytes('000000000000000000000000'),
  }), /kdf.length \(32\) does not match derived material length \(16\)/);

  assert.throws(() => registry.createDerivedKeyAead({
    algorithm: 'Missing-AEAD',
    kdf: {
      name: 'PBKDF2',
      input: 'secret',
      hash: 'SHA256',
      iterations: 1000,
    },
  }).seal(textToBytes('abc'), {
    salt: hexToBytes('0102030405060708'),
    nonce: hexToBytes('000000000000000000000000'),
  }), /Component not found: aead:Missing-AEAD/);

  const noKeySizesRegistry = createClassicRegistry()
    .use(classicHashesPreset)
    .use({
      kind: 'aead' as const,
      name: 'NoKeySizes',
      create() {
        return {
          createSealer() {
            return identityTransform();
          },
          createOpener() {
            return identityTransform();
          },
        };
      },
    });
  assert.throws(() => noKeySizesRegistry.createDerivedKeyAead({
    algorithm: 'NoKeySizes',
    kdf: {
      name: 'PBKDF2',
      input: 'secret',
      hash: 'SHA256',
      iterations: 1000,
    },
  }).seal(textToBytes('abc'), {
    salt: hexToBytes('0102030405060708'),
  }), /NoKeySizes derived-key AEAD requires keySize/);
});

test('createDerivedKeyAead rejects reserved operation option keys', () => {
  const salt = hexToBytes('0102030405060708');
  const nonce = hexToBytes('000000000000000000000000');
  const aead = registry.createDerivedKeyAead({
    algorithm: 'AES-GCM',
    kdf: {
      name: 'PBKDF2',
      input: 'secret',
      salt,
      hash: 'SHA256',
      iterations: 1000,
    },
    keySize: 16,
  });

  assert.throws(() => aead.seal(textToBytes('abc'), {
    nonce,
    kdf: 'PBKDF2',
  }), /reserved key: kdf/);
  assert.throws(() => aead.createSealer({
    nonce,
    format: 'OpenSSL',
  }).finalize(textToBytes('abc')), /reserved key: format/);
  assert.throws(() => aead.open(new Uint8Array(0), {
    nonce,
    keySize: 32,
  }), /reserved key: keySize/);
});

test('createDerivedKeyCipher derives IV length from classic modes', () => {
  const salt = hexToBytes('0102030405060708');
  const modes = [
    { mode: 'CFB' },
    { mode: 'CTR' },
    { mode: 'OFB' },
    { mode: 'ECB', padding: 'Pkcs7' },
  ];

  for (const { mode, padding } of modes) {
    const cipher = registry.createDerivedKeyCipher({
      cipher: 'AES',
      mode,
      ...(padding ? { padding } : {}),
      kdf: {
        name: 'PBKDF2',
        input: 'secret',
        hash: 'SHA256',
        iterations: 1000,
      },
      keySize: 16,
    });
    const encrypted = cipher.encrypt(textToBytes(`hello-${mode}`), { salt });
    assert.equal(bytesToText(cipher.decrypt(encrypted, { salt })), `hello-${mode}`);
  }

  const noIvMode = {
    kind: 'mode' as const,
    name: 'NoIv',
    requiresPadding: false,
    createEncryptor() {
      return identityTransform();
    },
    createDecryptor() {
      return identityTransform();
    },
  };
  const noIvRegistry = createClassicRegistry()
    .use(classicHashesPreset)
    .use(noIvMode);
  const noIvCipher = noIvRegistry.createDerivedKeyCipher({
    cipher: 'AES',
    mode: 'NoIv',
    kdf: {
      name: 'PBKDF2',
      input: 'secret',
      hash: 'SHA256',
      iterations: 1000,
    },
    keySize: 16,
  });
  assert.equal(bytesToText(noIvCipher.encrypt(textToBytes('abc'), { salt })), 'abc');

  const noModeCipher = registry.createDerivedKeyCipher({
    cipher: 'AES',
    kdf: {
      name: 'PBKDF2',
      input: 'secret',
      hash: 'SHA256',
      iterations: 1000,
    },
    keySize: 16,
  });
  assert.throws(() => noModeCipher.encrypt(textToBytes('abc'), { salt }), /requires a mode/);
});

test('createDerivedKeyCipher OpenSSL decrypt without header uses operation or creation salt', () => {
  const salt = hexToBytes('0001020304050607');
  const rawCipher = registry.createDerivedKeyCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    kdf: {
      name: 'EvpKDF',
      input: 'secret',
      hash: 'MD5',
      iterations: 1,
      salt,
    },
  });
  const rawEncrypted = rawCipher.encrypt(textToBytes('abc'));

  const operationSaltCipher = registry.createDerivedKeyCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    kdf: {
      name: 'EvpKDF',
      input: 'secret',
      hash: 'MD5',
      iterations: 1,
    },
    format: 'OpenSSL',
  });
  assert.equal(bytesToText(operationSaltCipher.decrypt(rawEncrypted, { salt })), 'abc');

  const creationSaltCipher = registry.createDerivedKeyCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    kdf: {
      name: 'EvpKDF',
      input: 'secret',
      hash: 'MD5',
      iterations: 1,
      salt,
    },
    format: 'OpenSSL',
  });
  assert.equal(bytesToText(creationSaltCipher.decrypt(rawEncrypted)), 'abc');

  const emptySaltRaw = registry.createDerivedKeyCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    kdf: {
      name: 'EvpKDF',
      input: 'secret',
      hash: 'MD5',
      iterations: 1,
    },
  });
  const emptySaltEncrypted = emptySaltRaw.encrypt(textToBytes('abc'), { salt: null });
  const emptySaltOpenSsl = registry.createDerivedKeyCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    kdf: {
      name: 'EvpKDF',
      input: 'secret',
      hash: 'MD5',
      iterations: 1,
    },
    format: 'OpenSSL',
  });
  assert.equal(bytesToText(emptySaltOpenSsl.decrypt(emptySaltEncrypted)), 'abc');
});

test('createDerivedKeyCipher requires salt without a format', () => {
  assert.throws(() => registry.createDerivedKeyCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    kdf: {
      name: 'PBKDF2',
      input: 'secret',
      hash: 'SHA256',
      iterations: 1,
    },
  }).encrypt(textToBytes('abc')), /requires salt/);

  const bufferedFormat = {
    kind: 'format' as const,
    name: 'DerivedBuffered',
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
  const localRegistry = createClassicRegistry().use(classicHashesPreset).use(bufferedFormat);
  assert.throws(() => localRegistry.createDerivedKeyCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    kdf: {
      name: 'EvpKDF',
      input: 'secret',
      hash: 'MD5',
      iterations: 1,
    },
    format: 'DerivedBuffered',
  }).encrypt(textToBytes('abc')), /requires salt/);
});

test('createDerivedKeyCipher allows missing salt when KDF does not require it', () => {
  const optionalSaltKdf = {
    kind: 'kdf' as const,
    name: 'OptionalSalt',
    derive(params: { input: string | Uint8Array; salt?: Uint8Array; length: number }) {
      const input = typeof params.input === 'string'
        ? new TextEncoder().encode(params.input)
        : params.input;
      const salt = params.salt instanceof Uint8Array ? params.salt : new Uint8Array(0);
      const out = new Uint8Array(params.length);
      for (let i = 0; i < out.length; i++) {
        const saltByte = salt.length === 0 ? 0 : salt[i % salt.length];
        out[i] = (input[i % input.length] ^ saltByte ^ i) & 0xff;
      }
      return out;
    },
  };
  const localRegistry = createClassicRegistry().use(optionalSaltKdf);
  const cipher = localRegistry.createDerivedKeyCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    kdf: {
      name: 'OptionalSalt',
      input: 'secret',
    },
    keySize: 32,
  });
  const encrypted = cipher.encrypt(textToBytes('abc'));
  assert.equal(bytesToText(cipher.decrypt(encrypted)), 'abc');
});

test('createDerivedKeyCipher rejects reserved operation option keys', () => {
  const salt = hexToBytes('0001020304050607');
  const cipher = registry.createDerivedKeyCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    kdf: {
      name: 'EvpKDF',
      input: 'secret',
      hash: 'MD5',
      iterations: 1,
      salt,
    },
  });
  assert.throws(() => cipher.encrypt(textToBytes('abc'), { key: new Uint8Array(32) }), /reserved key: key/);
  assert.throws(() => cipher.createEncryptor({ cipher: 'RC4' }), /reserved key: cipher/);
});

test('createDerivedKeyCipher rejects string kdf and length conflicts', () => {
  assert.throws(() => registry.createDerivedKeyCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    kdf: 'PBKDF2' as unknown as { name: string; input: string },
  }), /kdf to be an object/);

  assert.throws(() => registry.createDerivedKeyCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    kdf: {
      name: 'EvpKDF',
      input: 'secret',
      salt: new Uint8Array(8),
      hash: 'MD5',
      length: 16,
    },
  }).encrypt(textToBytes('abc')), /kdf.length/);
});

test('createDerivedKeyCipher streams OpenSSL output', () => {
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

test('createDerivedKeyCipher validates options and salt shapes', () => {
  assert.throws(() => registry.createDerivedKeyCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    kdf: {
      name: '',
      input: 'secret',
      salt: new Uint8Array(8),
    },
  }), /kdf.name/);

  assert.throws(() => registry.createDerivedKeyCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    kdf: {
      name: 'EvpKDF',
      salt: new Uint8Array(8),
      hash: 'MD5',
    },
  }), /requires input/);

  assert.throws(() => registry.createDerivedKeyCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    kdf: {
      name: 'EvpKDF',
      input: 'secret',
      salt: 123 as unknown as Uint8Array,
      hash: 'MD5',
    },
  }).encrypt(textToBytes('a')), /kdf.salt must be/);

  const withStringSalt = registry.createDerivedKeyCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    kdf: {
      name: 'EvpKDF',
      input: 'secret',
      salt: 'saltsalt',
      hash: 'MD5',
      iterations: 1,
      length: 48,
    },
  });
  assert.equal(bytesToText(withStringSalt.decrypt(withStringSalt.encrypt(textToBytes('abc')))), 'abc');

  const withNullSalt = registry.createDerivedKeyCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    kdf: {
      name: 'EvpKDF',
      input: 'secret',
      salt: null,
      hash: 'MD5',
      iterations: 1,
    },
  });
  assert.equal(bytesToText(withNullSalt.decrypt(withNullSalt.encrypt(textToBytes('abc')))), 'abc');

  assert.throws(() => registry.createDerivedKeyCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    kdf: {
      name: 'EvpKDF',
      input: 'secret',
      hash: 'MD5',
    },
  }).createDecryptor().finalize(textToBytes('a')), /requires salt/);
});

function identityTransform() {
  return {
    process(input: Uint8Array) {
      return input;
    },
    finalize(input = new Uint8Array(0)) {
      return input;
    },
  };
}
