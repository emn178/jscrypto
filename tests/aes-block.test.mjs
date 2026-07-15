import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createAesCipher } from '@jscrypto/classic';
import { bytesToHex, hexToBytes } from './helpers/bytes.mjs';

const plaintext = '00112233445566778899aabbccddeeff';

for (const { name, key, ciphertext } of [
  {
    name: 'AES-128',
    key: '000102030405060708090a0b0c0d0e0f',
    ciphertext: '69c4e0d86a7b0430d8cdb78070b4c55a',
  },
  {
    name: 'AES-192',
    key: '000102030405060708090a0b0c0d0e0f1011121314151617',
    ciphertext: 'dda97ca4864cdfe06eaf70a0ec0d7191',
  },
  {
    name: 'AES-256',
    key: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
    ciphertext: '8ea2b7ca516745bfeafc49904b496089',
  },
]) {
  test(`${name} encrypts and decrypts a FIPS-197 block`, () => {
    const cipher = createAesCipher(hexToBytes(key));
    const input = hexToBytes(plaintext);
    const encrypted = cipher.encryptBlock(input);

    assert.equal(bytesToHex(encrypted), ciphertext);
    assert.deepEqual(cipher.decryptBlock(encrypted), input);
    assert.equal(bytesToHex(input), plaintext);
  });
}
