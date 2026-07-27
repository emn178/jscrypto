import assert from 'node:assert/strict';
import { test } from 'node:test';
import { concatBytes } from '@jscrypto/core';
import { createClassicRegistry, registry } from '@jscrypto/classic';
import { classicHashesPreset } from '@jscrypto/classic/hashes';
import { bytesToHex, bytesToText, hexToBytes, textToBytes } from './helpers/bytes.mjs';

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

test('createDerivedKeyCipher matches createPassphraseCipher for OpenSSL EvpKDF', () => {
  const salt = hexToBytes('0001020304050607');
  const passphrase = registry.createPassphraseCipher({
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
    salt,
  });
  const derived = registry.createDerivedKeyCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    kdf: {
      name: 'EvpKDF',
      iterations: 1,
      hash: 'MD5',
      input: 'secret',
      salt,
    },
    format: 'OpenSSL',
  });

  const plaintext = textToBytes('abc');
  assert.equal(bytesToHex(derived.encrypt(plaintext)), bytesToHex(passphrase.encrypt(plaintext)));
  assert.equal(bytesToText(derived.decrypt(derived.encrypt(plaintext))), 'abc');
});

test('createDerivedKeyCipher matches createPassphraseCipher for PBKDF2', () => {
  const salt = hexToBytes('0102030405060708');
  const passphrase = registry.createPassphraseCipher({
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
    salt,
  });
  const derived = registry.createDerivedKeyCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    kdf: {
      name: 'PBKDF2',
      iterations: 1000,
      hash: 'SHA256',
      input: 'secret',
      salt,
    },
    format: 'OpenSSL',
  });

  const plaintext = textToBytes('hello');
  assert.equal(bytesToHex(derived.encrypt(plaintext)), bytesToHex(passphrase.encrypt(plaintext)));
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
    kind: 'mode',
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
    kind: 'format',
    name: 'DerivedBuffered',
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
    kind: 'kdf',
    name: 'OptionalSalt',
    derive(params) {
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
    kdf: 'PBKDF2',
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
      salt: 123,
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

test('createPassphraseCipher prefers kdf.input and kdf.salt when present', () => {
  const salt = hexToBytes('0001020304050607');
  const cipher = registry.createPassphraseCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    passphrase: 'ignored',
    salt: hexToBytes('ffffffffffffffff'),
    kdf: {
      name: 'EvpKDF',
      input: 'secret',
      salt,
      iterations: 1,
      hash: 'MD5',
    },
    format: 'OpenSSL',
  });

  assert.equal(
    bytesToHex(cipher.encrypt(textToBytes('abc'))),
    '53616c7465645f5f00010203040506074c87a9e77ccd8995cc1a9bd212d183c6',
  );
});

test('createPassphraseCipher preserves no-format random salt encrypt and empty-salt decrypt', () => {
  const cipher = registry.createPassphraseCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    passphrase: 'secret',
    kdf: 'EvpKDF',
  });
  const encrypted = cipher.encrypt(textToBytes('abc'));
  assert.ok(encrypted.length > 0);
  // Legacy decrypt without format uses an empty salt, matching previous behavior.
  assert.throws(() => cipher.decrypt(encrypted));

  const sized = registry.createPassphraseCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    passphrase: 'secret',
    kdf: 'EvpKDF',
    saltSize: 8,
  });
  assert.ok(sized.encrypt(textToBytes('abc')).length > 0);
});

test('KDF helpers require input', async () => {
  const { deriveEvpKdf, derivePbkdf2 } = await import('@jscrypto/classic');
  const { md5, sha256 } = await import('@jscrypto/classic/hashes');

  assert.equal(bytesToHex(deriveEvpKdf({
    input: 'password',
    salt: 'saltsalt',
    length: 16,
    hash: md5,
  })), 'fdbdf3419fff98bdb0241390f62a9db3');

  assert.throws(() => deriveEvpKdf({
    salt: 'saltsalt',
    length: 16,
    hash: md5,
  }), /requires input/);
  assert.throws(() => derivePbkdf2({
    salt: 'saltsalt',
    iterations: 1,
    length: 16,
    hash: sha256,
  }), /requires input/);
});

function identityTransform() {
  return {
    process(input) {
      return input;
    },
    finalize(input = new Uint8Array(0)) {
      return input;
    },
  };
}
