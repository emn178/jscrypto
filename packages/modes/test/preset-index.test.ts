import assert from 'node:assert/strict';
import { test } from 'node:test';
import { cbcPreset } from '../src/cbc.js';
import { cfbPreset } from '../src/cfb.js';
import { ctrPreset } from '../src/ctr.js';
import { ecbPreset } from '../src/ecb.js';
import { gcmPreset } from '../src/gcm.js';
import { ofbPreset } from '../src/ofb.js';
import { modesPreset } from '../src/preset.js';
import * as modesIndex from '../src/index.js';

test('modes preset exposes all block mode components', () => {
  assert.deepEqual(
    [...modesPreset().components()].map((component) => component.name),
    ['cbc', 'cfb', 'ctr', 'ecb', 'gcm', 'ofb'],
  );
});

test('individual mode presets expose their component', () => {
  assert.equal([...cbcPreset.components()][0].name, 'CBC');
  assert.equal([...cfbPreset.components()][0].name, 'CFB');
  assert.equal([...ctrPreset.components()][0].name, 'CTR');
  assert.equal([...ecbPreset.components()][0].name, 'ECB');
  assert.equal([...gcmPreset.components()][0].name, 'GCM');
  assert.equal([...ofbPreset.components()][0].name, 'OFB');
});

test('index re-exports mode components and preset', () => {
  assert.equal(modesIndex.cbc.name, 'CBC');
  assert.equal(modesIndex.cfb.name, 'CFB');
  assert.equal(modesIndex.ctr.name, 'CTR');
  assert.equal(modesIndex.ecb.name, 'ECB');
  assert.equal(modesIndex.gcm.name, 'GCM');
  assert.equal(modesIndex.ofb.name, 'OFB');
  assert.equal(typeof modesIndex.modesPreset, 'function');
});
