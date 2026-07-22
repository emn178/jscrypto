import assert from 'node:assert/strict';
import { test } from 'node:test';
import { MissingComponentError, concatBytes } from '@jscrypto/core';
import { createClassicRegistry, registry } from '@jscrypto/classic';
import { registerClassicHashes } from '@jscrypto/classic/hashes';
import { bytesToHex, bytesToText, hexToBytes, textToBytes } from './helpers/bytes.mjs';

registerClassicHashes(registry);

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
  }), (error) => error instanceof MissingComponentError);
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
    format: {
      name: 'OpenSSL',
      saltSize: 8,
    },
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

test('createDerivedKeyCipher accepts OpenSSL format shorthand and saltSize', () => {
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
  const encrypted = cipher.encrypt(textToBytes('abc'));
  assert.equal(bytesToHex(encrypted.subarray(0, 8)), '53616c7465645f5f');
  assert.equal(bytesToText(cipher.decrypt(encrypted)), 'abc');

  const sized = registry.createDerivedKeyCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    kdf: {
      name: 'EvpKDF',
      input: 'secret',
      hash: 'MD5',
      iterations: 1,
    },
    format: {
      name: 'OpenSSL',
      saltSize: 8,
    },
  });
  assert.equal(bytesToText(sized.decrypt(sized.encrypt(textToBytes('abc')))), 'abc');
});

test('createDerivedKeyCipher requires salt without a salt-generating format', () => {
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
  const localRegistry = registerClassicHashes(createClassicRegistry()).use(bufferedFormat);
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
