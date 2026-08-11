import assert from 'node:assert/strict';
import { createRegistry } from '@jscrypto/core';
import { test } from 'node:test';
import { bytesToHex, hexToBytes } from '../helpers/bytes.mjs';

const plaintext = '00112233445566778899aabbccddeeff';

test('AES component browser and node subpath builds expose raw block ciphers', async () => {
  const key = hexToBytes('000102030405060708090a0b0c0d0e0f');
  const input = hexToBytes(plaintext);
  const expected = '69c4e0d86a7b0430d8cdb78070b4c55a';

  for (const modulePath of [
    '../../packages/ciphers/dist/aes.mjs',
    '../../packages/ciphers/dist/aes.node.mjs',
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
  const { aes, createAesCipher } = await import('../../packages/ciphers/dist/aes.mjs');
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

test('Node AES dist path works when block cipher has no encryptBlock hook', async () => {
  const { aes, aesCcm } = await import('../../packages/ciphers/dist/aes.node.mjs');
  assert.equal(typeof aes.create(new Uint8Array(16)).encryptBlock, 'undefined');
  const registry = createRegistry().use(aes).use(aesCcm);
  const aead = registry.createAead({
    algorithm: 'AES-CCM',
    key: hexToBytes('c0c1c2c3c4c5c6c7c8c9cacbcccdcecf'),
  });
  const nonce = hexToBytes('00000003020100a0a1a2a3a4a5');
  const data = hexToBytes('08090a0b0c0d0e0f101112131415161718191a1b1c1d1e');
  const aad = hexToBytes('0001020304050607');
  const sealed = aead.seal(data, { nonce, aad, tagLength: 8 });
  assert.equal(
    bytesToHex(sealed),
    '588c979a61c663d2f066d0c2c0f989806d5f6b61dac38417e8d12cfdf926e0',
  );
});

test('browser AES dist encryptBlock path also seals correctly', async () => {
  const { aes: browserAes, aesCcm: browserAesCcm } = await import(
    '../../packages/ciphers/dist/aes.mjs'
  );
  assert.equal(typeof browserAes.create(new Uint8Array(16)).encryptBlock, 'function');

  const registry = createRegistry().use(browserAes).use(browserAesCcm);
  const aead = registry.createAead({
    algorithm: 'AES-CCM',
    key: hexToBytes('c0c1c2c3c4c5c6c7c8c9cacbcccdcecf'),
  });
  const nonce = hexToBytes('00000003020100a0a1a2a3a4a5');
  const data = hexToBytes('08090a0b0c0d0e0f101112131415161718191a1b1c1d1e');
  const aad = hexToBytes('0001020304050607');
  const sealed = aead.seal(data, { nonce, aad, tagLength: 8 });
  assert.equal(
    bytesToHex(sealed),
    '588c979a61c663d2f066d0c2c0f989806d5f6b61dac38417e8d12cfdf926e0',
  );
});
