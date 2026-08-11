import assert from 'node:assert/strict';
import type { PresetComponent } from '@jscrypto/core';
import { test } from 'node:test';
import * as index from '../src/index.js';
import {
  argon2,
  argon2Preset,
} from '../src/argon2.js';
import {
  evpKdf,
  evpKdfPreset,
} from '../src/evpkdf.js';
import {
  hkdf,
  hkdfExpand,
  hkdfExtract,
  hkdfPreset,
} from '../src/hkdf.js';
import { hmac } from '../src/hmac.js';
import {
  pbkdf2,
  pbkdf2Preset,
} from '../src/pbkdf2.js';
import {
  classicKdfsPreset,
  kdfsPreset,
} from '../src/preset.js';
import {
  scrypt,
  scryptPreset,
} from '../src/scrypt.js';
import { sha256 } from '@jscrypto/hashes';

test('classic and full kdf presets expose expected component graphs', () => {
  assert.deepEqual(
    [...classicKdfsPreset().components()].map((component) => component.name),
    ['pbkdf2', 'evpkdf'],
  );
  assert.deepEqual(
    [...kdfsPreset().components()].map((component) => component.name),
    ['classic-kdfs', 'hkdf', 'scrypt', 'argon2'],
  );
});

test('index re-exports kdf surfaces', () => {
  assert.equal(index.evpKdf.name, 'EvpKDF');
  assert.equal(index.pbkdf2.name, 'PBKDF2');
  assert.equal(index.hkdf.name, 'HKDF');
  assert.equal(index.hkdfExtract.name, 'HKDF-Extract');
  assert.equal(index.hkdfExpand.name, 'HKDF-Expand');
  assert.equal(index.scrypt.name, 'Scrypt');
  assert.equal(index.argon2.name, 'Argon2');
  assert.equal(typeof index.deriveEvpKdf, 'function');
  assert.equal(typeof index.derivePbkdf2, 'function');
  assert.equal(typeof index.deriveHkdf, 'function');
  assert.equal(typeof index.deriveScrypt, 'function');
  assert.equal(typeof index.deriveArgon2, 'function');
  assert.equal(typeof index.hmac, 'function');
  assert.equal(index.evpKdfPreset.name, 'evpkdf');
  assert.equal(index.pbkdf2Preset.name, 'pbkdf2');
  assert.equal(index.hkdfPreset.name, 'hkdf');
  assert.equal(index.scryptPreset.name, 'scrypt');
  assert.equal(index.argon2Preset.name, 'argon2');
  assert.deepEqual([...index.classicKdfsPreset().components()], [pbkdf2Preset, evpKdfPreset]);
  assert.deepEqual(
    [...index.kdfsPreset().components()].map((component) => component.name),
    ['classic-kdfs', 'hkdf', 'scrypt', 'argon2'],
  );
});

test('nested presets register all kdf components', () => {
  const names = [...kdfsPreset().components()].flatMap((preset) =>
    [...(preset as PresetComponent).components()].map((component) => component.name),
  );
  assert.deepEqual(names, [
    'pbkdf2',
    'evpkdf',
    'HKDF',
    'HKDF-Extract',
    'HKDF-Expand',
    'Scrypt',
    'Argon2',
  ]);
  assert.equal([...hkdfPreset.components()].length, 3);
  assert.equal([...scryptPreset.components()][0], scrypt);
  assert.equal([...argon2Preset.components()][0], argon2);
  assert.equal([...evpKdfPreset.components()][0], evpKdf);
  assert.equal([...pbkdf2Preset.components()][0], pbkdf2);
});

test('hmac normalizes keys longer than the hash block size', () => {
  const longKey = new Uint8Array(sha256.blockSize + 1);
  longKey.fill(0x42);
  const shortKey = new Uint8Array(16);
  shortKey.fill(0x42);

  const fromLong = hmac(sha256, longKey, new TextEncoder().encode('message'));
  const fromHashed = hmac(sha256, sha256.hash(longKey), new TextEncoder().encode('message'));
  assert.deepEqual(fromLong, fromHashed);
  assert.notDeepEqual(hmac(sha256, shortKey, new TextEncoder().encode('message')), fromLong);
});
