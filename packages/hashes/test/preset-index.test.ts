import assert from 'node:assert/strict';
import { test } from 'node:test';
import * as index from '../src/index.js';
import {
  classicHashesPreset,
  hashesPreset,
  keccak512,
  md5,
  ripemd160,
  sha1,
  sha224,
  sha256,
  sha384,
  sha512,
} from '../src/index.js';
import { keccak512Preset } from '../src/sha3.js';
import { md5Preset } from '../src/md5.js';
import { ripemd160Preset } from '../src/ripemd160.js';
import { sha1Preset } from '../src/sha1.js';
import { sha224Preset } from '../src/sha224.js';
import { sha256Preset } from '../src/sha256.js';
import { sha384Preset } from '../src/sha384.js';
import { sha512Preset } from '../src/sha512.js';
import { createHash } from '../src/component.js';
import { bytesToHex, textToBytes } from './helpers/bytes.js';

test('hashes preset exposes classic hash components', () => {
  assert.deepEqual(
    [...hashesPreset.components()].map((component) => component.name),
    ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'keccak512', 'ripemd160'],
  );
  assert.equal(classicHashesPreset.name, 'classic-hashes');
  assert.deepEqual([...classicHashesPreset.components()], [...hashesPreset.components()]);
});

test('individual hash presets expose their hash components', () => {
  assert.deepEqual([...md5Preset.components()], [md5]);
  assert.deepEqual([...sha1Preset.components()], [sha1]);
  assert.deepEqual([...sha224Preset.components()], [sha224]);
  assert.deepEqual([...sha256Preset.components()], [sha256]);
  assert.deepEqual([...sha384Preset.components()], [sha384]);
  assert.deepEqual([...sha512Preset.components()], [sha512]);
  assert.deepEqual([...keccak512Preset.components()], [keccak512]);
  assert.deepEqual([...ripemd160Preset.components()], [ripemd160]);
});

test('index re-exports hash surfaces', () => {
  assert.equal(index.md5.name, 'MD5');
  assert.equal(index.sha256.name, 'SHA256');
  assert.equal(index.keccak512.name, 'KECCAK512');
  assert.equal(index.ripemd160.name, 'RIPEMD160');
  assert.equal(typeof index.createHash, 'function');
  assert.equal(index.hashesPreset.name, 'hashes');
});

test('createHash builds hash components with metadata', () => {
  const custom = createHash('CUSTOM', 32, 16, () => new Uint8Array(16));
  assert.equal(custom.kind, 'hash');
  assert.equal(custom.name, 'CUSTOM');
  assert.equal(custom.blockSize, 32);
  assert.equal(custom.digestSize, 16);
  assert.deepEqual(custom.hash(new Uint8Array()), new Uint8Array(16));
});

test('hash algorithms match known digests', () => {
  const cases = [
    [md5, 'abc', '900150983cd24fb0d6963f7d28e17f72'],
    [sha1, 'abc', 'a9993e364706816aba3e25717850c26c9cd0d89d'],
    [sha224, 'abc', '23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7'],
    [sha256, 'abc', 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'],
    [sha384, 'abc', 'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7'],
    [sha512, 'abc', 'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f'],
    [keccak512, 'abc', '18587dc2ea106b9a1563e32b3312421ca164c7f1f07bc922a9c83d77cea3a1e5d0c69910739025372dc14ac9642629379540c17e2a65b19d77aa511a9d00bb96'],
    [ripemd160, 'abc', '8eb208f7e05d987a9b044a8e98c6b087f15a0bfc'],
  ] as const;

  for (const [hash, input, expected] of cases) {
    assert.equal(bytesToHex(hash.hash(textToBytes(input))), expected, hash.name);
  }
});

test('long inputs exercise ripemd160 round branches', () => {
  const longInput = textToBytes('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq');
  assert.equal(
    bytesToHex(ripemd160.hash(longInput)),
    '12a053384a9c0c88e405a06c27dcf49ada62eb2b',
  );
  const paddedBoundary = new Uint8Array(55);
  paddedBoundary.fill(0x61);
  assert.equal(ripemd160.hash(paddedBoundary).length, 20);
});
