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
    const encrypted = new Uint8Array(input.length);
    const decrypted = new Uint8Array(input.length);

    assert.equal(cipher.encrypt(input, encrypted), encrypted);
    assert.equal(bytesToHex(encrypted), ciphertext);
    assert.equal(cipher.decrypt(encrypted, decrypted), decrypted);
    assert.deepEqual(decrypted, input);
    assert.equal(bytesToHex(input), plaintext);
  });

  test(`${name} encrypts and decrypts multiple raw blocks`, () => {
    const cipher = createAesCipher(hexToBytes(key));
    const input = hexToBytes(`${plaintext}${plaintext}`);
    const output = new Uint8Array(input.length);
    const encrypted = cipher.encrypt(input, output);

    assert.equal(encrypted, output);
    assert.equal(bytesToHex(encrypted), `${ciphertext}${ciphertext}`);
    assert.deepEqual(cipher.decrypt(encrypted, new Uint8Array(encrypted.length)), input);
  });

  test(`${name} encrypts and decrypts multiple raw blocks in place`, () => {
    const cipher = createAesCipher(hexToBytes(key));
    const input = hexToBytes(`${plaintext}${plaintext}`);
    const encrypted = input.slice();

    assert.equal(cipher.encrypt(encrypted, encrypted), encrypted);
    assert.equal(bytesToHex(encrypted), `${ciphertext}${ciphertext}`);
    assert.equal(cipher.decrypt(encrypted, encrypted), encrypted);
    assert.deepEqual(encrypted, input);
  });
}

test('AES raw block API validates input and output lengths', () => {
  const cipher = createAesCipher(new Uint8Array(16));

  assert.throws(() => cipher.encrypt(new Uint8Array(15), new Uint8Array(15)), /multiple of 128 bits/);
  assert.throws(() => cipher.decrypt(new Uint8Array(16), new Uint8Array(15)), /output length/);
  assert.throws(() => cipher.decrypt(new Uint8Array(16), new Uint8Array(17)), /output length/);
});

test('AES component browser and node subpath builds expose raw block ciphers', async () => {
  const key = hexToBytes('000102030405060708090a0b0c0d0e0f');
  const input = hexToBytes(plaintext);
  const expected = '69c4e0d86a7b0430d8cdb78070b4c55a';

  for (const modulePath of [
    '../packages/ciphers/dist/aes.mjs',
    '../packages/ciphers/dist/aes.node.mjs',
  ]) {
    const { aes, createAesCipher } = await import(modulePath);
    const cipher = createAesCipher(key);
    const encrypted = new Uint8Array(input.length);
    const decrypted = new Uint8Array(input.length);

    assert.throws(() => createAesCipher(new Uint8Array(15)), /AES key/);
    assert.equal(cipher.encrypt(input, encrypted), encrypted);
    assert.equal(bytesToHex(encrypted), expected);
    assert.equal(cipher.decrypt(encrypted, decrypted), decrypted);
    assert.deepEqual(decrypted, input);

    assert.equal(aes.create(key).blockSize, 16);
    assert.throws(() => cipher.encrypt(new Uint8Array(15), new Uint8Array(15)), /multiple of 128 bits/);
    assert.throws(() => cipher.decrypt(new Uint8Array(16), new Uint8Array(15)), /output length/);
  }
});

test('AES browser subpath build exposes block-offset helpers', async () => {
  const { aes, createAesCipher } = await import('../packages/ciphers/dist/aes.mjs');
  const key = hexToBytes('000102030405060708090a0b0c0d0e0f');
  const input = hexToBytes(`00000000000000000000000000000000${plaintext}`);
  const encrypted = new Uint8Array(input.length);
  const decrypted = new Uint8Array(input.length);
  const cipher = createAesCipher(key);

  assert.equal(aes.create(key).blockSize, 16);
  cipher.encryptBlock(input, 16, encrypted, 0);
  assert.equal(bytesToHex(encrypted.subarray(0, 16)), '69c4e0d86a7b0430d8cdb78070b4c55a');
  cipher.decryptBlock(encrypted, 0, decrypted, 16);
  assert.equal(bytesToHex(decrypted.subarray(16)), plaintext);
  assert.throws(() => cipher.encrypt(new Uint8Array(15), new Uint8Array(15)), /multiple of 128 bits/);
  assert.throws(() => cipher.decrypt(new Uint8Array(16), new Uint8Array(15)), /output length/);
});
