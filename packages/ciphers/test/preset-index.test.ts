import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  ciphersPreset,
  classicCiphersPreset,
} from '../src/preset.js';
import {
  ciphersPreset as nodeCiphersPreset,
  classicCiphersPreset as nodeClassicCiphersPreset,
} from '../src/preset-node.js';
import * as browserIndex from '../src/index.js';
import * as nodeIndex from '../src/index-node.js';

test('browser and node presets expose classic and full cipher graphs', () => {
  assert.deepEqual(
    [...classicCiphersPreset().components()].map((component) => component.name),
    ['aes', 'des', 'rc4', 'triple-des'],
  );
  assert.deepEqual(
    [...ciphersPreset().components()].map((component) => component.name),
    ['classic-ciphers', 'speck', 'chacha20'],
  );
  assert.deepEqual(
    [...nodeClassicCiphersPreset().components()].map((component) => component.name),
    ['aes', 'des', 'rc4', 'triple-des'],
  );
  assert.deepEqual(
    [...nodeCiphersPreset().components()].map((component) => component.name),
    ['classic-ciphers', 'speck', 'chacha20'],
  );
});

test('browser and node index entries re-export cipher surfaces', () => {
  assert.equal(browserIndex.aes.name, 'AES');
  assert.equal(browserIndex.aesGcm.name, 'AES-GCM');
  assert.equal(browserIndex.aesCcm.name, 'AES-CCM');
  assert.equal(browserIndex.des.name, 'DES');
  assert.equal(browserIndex.rc4.name, 'RC4');
  assert.equal(browserIndex.speck64_128.name, 'SPECK64/128');
  assert.equal(browserIndex.allSpeckComponents.length, 10);
  assert.equal(nodeIndex.aes.name, 'AES');
  assert.equal(typeof nodeIndex.createAesCipher, 'function');
  assert.equal(typeof browserIndex.createAesCipher, 'function');
});
