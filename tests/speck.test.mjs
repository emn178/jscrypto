import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { test } from 'node:test';
import { createRegistry } from '@jscrypto/core';
import { cbc, ecb, noPadding, pkcs7 } from '@jscrypto/suite';
import {
  allSpeckComponents,
  createSpeckCipher,
  speck64_128,
  speckPreset,
} from '../packages/ciphers/dist/speck.mjs';

const require = createRequire(import.meta.url);

const vectors = [
  {
    variant: '32-64',
    name: 'SPECK32/64',
    key: '0001080910111819',
    plaintext: '4c697465',
    ciphertext: 'f24268a8',
  },
  {
    variant: '48-72',
    name: 'SPECK48/72',
    key: '00010208090a101112',
    plaintext: '72616c6c7920',
    ciphertext: 'dc5a38a549c0',
  },
  {
    variant: '48-96',
    name: 'SPECK48/96',
    key: '00010208090a10111218191a',
    plaintext: '74686973206d',
    ciphertext: '5d44b6105e73',
  },
  {
    variant: '64-96',
    name: 'SPECK64/96',
    key: '0001020308090a0b10111213',
    plaintext: '65616e7320466174',
    ciphertext: '6c947541ec52799f',
  },
  {
    variant: '64-128',
    name: 'SPECK64/128',
    key: '0001020308090a0b1011121318191a1b',
    plaintext: '2d4375747465723b',
    ciphertext: '8b024e4548a56f8c',
  },
  {
    variant: '96-96',
    name: 'SPECK96/96',
    key: '00010203040508090a0b0c0d',
    plaintext: '207468652070696c6c617220',
    ciphertext: '12e785d8e391fa7308a70147',
  },
  {
    variant: '96-144',
    name: 'SPECK96/144',
    key: '00010203040508090a0b0c0d101112131415',
    plaintext: '6f6620647573742074686174',
    ciphertext: 'bcba8e3d3642895817109732',
  },
  {
    variant: '128-128',
    name: 'SPECK128/128',
    key: '000102030405060708090a0b0c0d0e0f',
    plaintext: '206d616465206974206571756976616c',
    ciphertext: '180d575cdffe60786532787951985da6',
  },
  {
    variant: '128-192',
    name: 'SPECK128/192',
    key: '000102030405060708090a0b0c0d0e0f1011121314151617',
    plaintext: '656e7420746f20436869656620486172',
    ciphertext: '86183ce05d18bcf9665513133acfe41b',
  },
  {
    variant: '128-256',
    name: 'SPECK128/256',
    key: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
    plaintext: '706f6f6e65722e20496e2074686f7365',
    ciphertext: '438f189c8db4ee4e3ef5c00504010941',
  },
];

function hex(value) {
  return Uint8Array.from(Buffer.from(value, 'hex'));
}

function toHex(bytes) {
  return Buffer.from(bytes).toString('hex');
}

test('createSpeckCipher matches known vectors for every variant', () => {
  for (const vector of vectors) {
    const key = hex(vector.key);
    const plaintext = hex(vector.plaintext);
    const cipher = createSpeckCipher(vector.variant, key);
    const encrypted = new Uint8Array(plaintext.length);
    const decrypted = new Uint8Array(plaintext.length);
    cipher.encrypt(plaintext, encrypted);
    cipher.decrypt(encrypted, decrypted);

    assert.equal(cipher.blockSize, plaintext.length);
    assert.equal(toHex(encrypted), vector.ciphertext);
    assert.deepEqual(decrypted, plaintext);
  }
});

test('createSpeckCipher encryptBlock/decryptBlock write into caller-owned buffers', () => {
  const vector = vectors.find((item) => item.variant === '64-128');
  const key = hex(vector.key);
  const plaintext = hex(vector.plaintext);
  const cipher = createSpeckCipher(vector.variant, key);
  const encrypted = new Uint8Array(plaintext.length);
  const decrypted = new Uint8Array(plaintext.length);

  cipher.encryptBlock(plaintext, 0, encrypted, 0);
  cipher.decryptBlock(encrypted, 0, decrypted, 0);

  assert.equal(toHex(encrypted), vector.ciphertext);
  assert.deepEqual(decrypted, plaintext);
});

test('registry ECB + NoPadding reproduces raw SPECK64/128 block output', () => {
  const vector = vectors.find((item) => item.variant === '64-128');
  const key = hex(vector.key);
  const plaintext = hex(vector.plaintext);
  const registry = createRegistry().use(speck64_128).use(ecb).use(noPadding);
  const cipher = registry.createCipher({
    cipher: 'SPECK64/128',
    mode: 'ECB',
    padding: 'NoPadding',
    key,
  });

  assert.equal(toHex(cipher.encrypt(plaintext)), vector.ciphertext);
  assert.deepEqual(cipher.decrypt(hex(vector.ciphertext)), plaintext);
});

test('registry CBC + Pkcs7 encrypts and decrypts with SPECK64/128', () => {
  const key = hex('0001020308090a0b1011121318191a1b');
  const iv = hex('0001020304050607');
  const plaintext = hex('00112233445566778899aabb');
  const registry = createRegistry().use(speck64_128).use(cbc).use(pkcs7);
  const cipher = registry.createCipher({
    cipher: 'SPECK64/128',
    mode: 'CBC',
    padding: 'Pkcs7',
    key,
    iv,
  });

  const ciphertext = cipher.encrypt(plaintext);
  assert.equal(ciphertext.length % 8, 0);
  assert.deepEqual(cipher.decrypt(ciphertext), plaintext);
});

test('speckPreset registers every SPECK component', () => {
  const registry = createRegistry().use(speckPreset);
  assert.equal(allSpeckComponents.length, 10);
  for (const component of allSpeckComponents) {
    assert.equal(registry.has('cipher', component.name), true);
  }
});

test('rejects missing, invalid, wrong key, and wrong block inputs', () => {
  const key = hex('0001020308090a0b1011121318191a1b');

  assert.throws(
    () => createSpeckCipher(/** @type {any} */ (undefined), key),
    /SPECK variant is required\./,
  );
  assert.throws(
    () => createSpeckCipher(/** @type {any} */ (null), key),
    /SPECK variant is required\./,
  );
  assert.throws(
    () => createSpeckCipher(/** @type {any} */ ('64/128'), key),
    /Unknown SPECK variant: 64\/128\./,
  );
  assert.throws(
    () => createSpeckCipher('64-128', hex('0001020308090a0b10111213')),
    /SPECK 64-128 key must be 128 bits\./,
  );

  const cipher = createSpeckCipher('64-128', key);
  const shortBlock = hex('2d437574746572');
  const longBlock = hex('8b024e4548a56f8c00');
  assert.throws(
    () => cipher.encrypt(shortBlock, new Uint8Array(shortBlock.length)),
    /SPECK input length must be a multiple of 64 bits\./,
  );
  assert.throws(
    () => cipher.decrypt(longBlock, new Uint8Array(longBlock.length)),
    /SPECK input length must be a multiple of 64 bits\./,
  );
  assert.throws(
    () => cipher.encrypt(hex('2d4375747465723b'), new Uint8Array(7)),
    /SPECK output length must equal input length\./,
  );
  assert.throws(
    () => cipher.encryptBlock(shortBlock, 0, new Uint8Array(8), 0),
    /SPECK block must be 64 bits\./,
  );
});

test('component create validates key length', () => {
  assert.throws(
    () => speck64_128.create(hex('0001020308090a0b10111213')),
    /SPECK 64-128 key must be 128 bits\./,
  );
});

test('CommonJS build can be required', () => {
  const speck = require('../packages/ciphers/dist/speck.cjs');
  assert.equal(typeof speck.createSpeckCipher, 'function');
  assert.equal(speck.createRegistry, undefined);
  assert.equal(speck.speck64_128.name, 'SPECK64/128');
  assert.equal(speck.speckPreset.name, 'speck');
});

test('generated declarations export the public API', async () => {
  const dts = await readFile(new URL('../packages/ciphers/dist/speck.d.ts', import.meta.url), 'utf8');
  assert.match(dts, /export type SpeckVariantName =/);
  assert.match(dts, /export declare const speck64_128:/);
  assert.match(dts, /export declare const speckPreset:/);
  assert.match(dts, /export declare const allSpeckComponents:/);
  assert.match(dts, /export declare function createSpeckCipher/);
  assert.doesNotMatch(dts, /createRegistry/);
});
