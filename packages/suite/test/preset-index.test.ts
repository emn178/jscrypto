import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  allPreset,
  allRegistry,
  createAllRegistry,
} from '../src/all.js';
import {
  basicPreset,
  createBasicRegistry,
  registry as basicRegistry,
} from '../src/basic.js';
import * as suiteIndex from '../src/index.js';

test('basicPreset registers the expected component graph', () => {
  assert.deepEqual(
    [...basicPreset().components()].map((component) => `${component.kind}:${component.name}`),
    [
      'preset:aes',
      'mode:CBC',
      'mode:CFB',
      'mode:CTR',
      'mode:ECB',
      'mode:GCM',
      'mode:OFB',
      'padding:Pkcs5',
      'padding:NoPadding',
      'padding:Pkcs7',
      'kdf:PBKDF2',
      'preset:hkdf',
      'format:OpenSSL',
      'preset:hashes',
    ],
  );
});

test('allPreset registers full package presets', () => {
  assert.deepEqual(
    [...allPreset().components()].map((component) => component.name),
    ['ciphers', 'modes', 'paddings', 'kdfs', 'formats', 'hashes'],
  );
});

test('basic and all registries can be created and reused', () => {
  const basic = createBasicRegistry();
  const all = createAllRegistry();
  assert.equal(basic.has('cipher', 'AES'), true);
  assert.equal(basic.has('aead', 'AES-GCM'), true);
  assert.equal(all.has('cipher', 'ChaCha20'), true);
  assert.equal(all.has('cipher', 'SPECK64/128'), true);
  assert.equal(basicRegistry.has('cipher', 'AES'), true);
  assert.equal(allRegistry.has('cipher', 'AES'), true);
});

test('suite index re-exports package surfaces and aliases', () => {
  assert.equal(suiteIndex.aes.name, 'AES');
  assert.equal(suiteIndex.cbc.name, 'CBC');
  assert.equal(suiteIndex.pkcs7.name, 'Pkcs7');
  assert.equal(suiteIndex.pbkdf2.name, 'PBKDF2');
  assert.equal(suiteIndex.opensslFormat.name, 'OpenSSL');
  assert.equal(suiteIndex.sha256.name, 'SHA256');
  assert.equal(suiteIndex.suitePreset().name, 'basic');
  assert.equal(suiteIndex.createSuiteRegistry().has('cipher', 'AES'), true);
  assert.equal(suiteIndex.registry.has('cipher', 'AES'), true);
  assert.equal(suiteIndex.createAllRegistry().has('cipher', 'RC4'), true);
});
