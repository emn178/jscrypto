import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { test } from 'node:test';
import { createRegistry } from '@jscrypto/core';
import {
  argon2,
  argon2Preset,
  deriveArgon2,
} from '../packages/kdfs/dist/argon2.mjs';
import {
  deriveScrypt,
  scrypt,
  scryptPreset,
} from '../packages/kdfs/dist/scrypt.mjs';
import { kdfsPreset } from '../packages/kdfs/dist/index.mjs';
import { bytesToHex } from './helpers/bytes.mjs';

const require = createRequire(import.meta.url);

test('Scrypt matches RFC 7914 password/NaCl vector', () => {
  const derived = deriveScrypt({
    input: 'password',
    salt: 'NaCl',
    N: 1024,
    r: 8,
    p: 16,
    length: 64,
  });

  assert.equal(
    bytesToHex(derived),
    'fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162' +
      '2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640',
  );
});

test('Scrypt component works through the registry', () => {
  const registry = createRegistry().use(scryptPreset);
  const derived = registry.derive({
    name: 'Scrypt',
    input: 'password',
    salt: 'NaCl',
    N: 1024,
    r: 8,
    p: 16,
    length: 64,
  });

  assert.equal(derived.length, 64);
});

test('Scrypt validates params', () => {
  assert.throws(() => deriveScrypt(undefined), /Scrypt requires params/);
  assert.throws(() => deriveScrypt({
    input: 'password',
    salt: 'salt',
    N: 1000,
    r: 8,
    p: 1,
    length: 32,
  }), /Scrypt N must be a power of 2/);
  assert.throws(() => deriveScrypt({
    input: 'password',
    salt: 'salt',
    N: 1024,
    r: 8,
    p: 1,
    length: 0,
  }), /Scrypt length must be a positive integer/);
});

test('Argon2id derives password/somesalt vector', () => {
  const derived = deriveArgon2({
    input: 'password',
    salt: 'somesalt',
    mode: 'id',
    m: 16,
    t: 2,
    p: 1,
    length: 32,
  });

  assert.equal(
    bytesToHex(derived),
    '058202c0723cd88c24408ccac1cbf828dee63bcf3843a150ea364a1e0b4e1ff8',
  );
});

test('Argon2 component defaults to Argon2id and works through the registry', () => {
  const registry = createRegistry().use(argon2Preset);
  const derived = registry.derive({
    name: 'Argon2',
    input: 'password',
    salt: 'somesalt',
    m: 16,
    t: 2,
    p: 1,
    length: 32,
  });

  assert.equal(
    bytesToHex(derived),
    '058202c0723cd88c24408ccac1cbf828dee63bcf3843a150ea364a1e0b4e1ff8',
  );
});

test('Argon2 validates params', () => {
  assert.throws(() => deriveArgon2(undefined), /Argon2 requires params/);
  assert.throws(() => deriveArgon2({
    input: 'password',
    salt: 'somesalt',
    mode: 'bad',
    m: 16,
    t: 2,
    p: 1,
    length: 32,
  }), /Argon2 mode must be 'id', 'i', or 'd'/);
  assert.throws(() => deriveArgon2({
    input: 'password',
    salt: 'short',
    mode: 'id',
    m: 16,
    t: 2,
    p: 1,
    length: 32,
  }), /salt/);
});

test('kdfsPreset registers Scrypt and Argon2', () => {
  const registry = createRegistry().use(kdfsPreset());
  assert.equal(registry.get('kdf', 'Scrypt').name, scrypt.name);
  assert.equal(registry.get('kdf', 'Argon2').name, argon2.name);
});

test('CommonJS builds can be required', () => {
  const scryptExports = require('../packages/kdfs/dist/scrypt.cjs');
  const argon2Exports = require('../packages/kdfs/dist/argon2.cjs');
  assert.equal(typeof scryptExports.deriveScrypt, 'function');
  assert.equal(scryptExports.scrypt.name, 'Scrypt');
  assert.equal(scryptExports.scryptPreset.name, 'scrypt');
  assert.equal(typeof argon2Exports.deriveArgon2, 'function');
  assert.equal(argon2Exports.argon2.name, 'Argon2');
  assert.equal(argon2Exports.argon2Preset.name, 'argon2');
});
