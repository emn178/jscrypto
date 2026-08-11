import assert from 'node:assert/strict';
import { test } from 'node:test';
import { concatBytes } from '@jscrypto/core';
import { ansiX923, iso10126, iso97971 } from '@jscrypto/paddings';
import { createClassicRegistry } from './helpers/classic-registry.js';
import { bytesToHex, bytesToText, hexToBytes, textToBytes } from './helpers/bytes.js';

const key = hexToBytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
const iv = hexToBytes('000102030405060708090a0b0c0d0e0f');

const fixedPaddingCases = [
  {
    name: 'Iso97971',
    ciphertext: '91dc27722f32ed12fbaae1e76282e8bc',
  },
  {
    name: 'AnsiX923',
    ciphertext: 'e68a3f710bdec4665b9506a48c9f835d',
  },
  {
    name: 'ZeroPadding',
    ciphertext: 'f2a13582a326d1e86d835ecd5cbb7e52',
  },
] as const;

for (const { name, ciphertext: expectedCiphertext } of fixedPaddingCases) {
  test(`AES-256-CBC streams encryption and decryption with ${name}`, () => {
    const plaintext = textToBytes('abc');
    const registry = createClassicRegistry();

    const encryptor = registry.createEncryptor({
      cipher: 'AES',
      mode: 'CBC',
      padding: name,
      key,
      iv,
    });
    const ciphertext = concatBytes(
      encryptor.process(plaintext.subarray(0, 1)),
      encryptor.process(plaintext.subarray(1)),
      encryptor.finalize(),
    );

    assert.equal(bytesToHex(ciphertext), expectedCiphertext);

    const decryptor = registry.createDecryptor({
      cipher: 'AES',
      mode: 'CBC',
      padding: name,
      key,
      iv,
    });
    const decrypted = concatBytes(
      decryptor.process(ciphertext.subarray(0, 7)),
      decryptor.process(ciphertext.subarray(7)),
      decryptor.finalize(),
    );

    assert.equal(bytesToText(decrypted), 'abc');
  });
}

test('AES-256-CBC streams encryption and decryption with Iso10126', () => {
  const plaintext = textToBytes('abc');
  const registry = createClassicRegistry();

  const encryptor = registry.createEncryptor({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Iso10126',
    key,
    iv,
  });
  const ciphertext = concatBytes(
    encryptor.process(plaintext.subarray(0, 2)),
    encryptor.process(plaintext.subarray(2)),
    encryptor.finalize(),
  );

  assert.equal(ciphertext.length, 16);

  const decryptor = registry.createDecryptor({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Iso10126',
    key,
    iv,
  });
  const decrypted = concatBytes(
    decryptor.process(ciphertext.subarray(0, 4)),
    decryptor.process(ciphertext.subarray(4)),
    decryptor.finalize(),
  );

  assert.equal(bytesToText(decrypted), 'abc');
});

test('AnsiX923 rejects non-zero padding bytes', () => {
  assert.throws(
    () => ansiX923.unpad(hexToBytes('6162630100000000000000000000010d'), 16),
    /Invalid ANSI X9.23/,
  );
});

test('Iso97971 rejects missing 0x80 marker', () => {
  assert.throws(
    () => iso97971.unpad(hexToBytes('61626300000000000000000000000000'), 16),
    /Invalid ISO\/IEC 9797-1/,
  );
});
