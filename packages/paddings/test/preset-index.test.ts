import assert from 'node:assert/strict';
import { test } from 'node:test';
import { padPkcs, unpadPkcs } from '../src/pkcs-shared.js';
import { ansiX923Preset } from '../src/ansi-x923.js';
import { iso10126Preset } from '../src/iso10126.js';
import { iso97971Preset } from '../src/iso97971.js';
import { noPaddingPreset } from '../src/none.js';
import { pkcs5Preset } from '../src/pkcs5.js';
import { pkcs7Preset } from '../src/pkcs7.js';
import { zeroPaddingPreset } from '../src/zero.js';
import { paddingsPreset } from '../src/preset.js';
import * as paddingsIndex from '../src/index.js';
import { bytesToHex, textToBytes } from './helpers/bytes.js';

test('pkcs-shared pad and unpad round-trip', () => {
  const input = textToBytes('hello');
  const padded = padPkcs(input, 16);
  assert.equal(padded.length % 16, 0);
  assert.deepEqual(unpadPkcs(padded, 16), input);
});

test('pkcs-shared rejects invalid padding bytes', () => {
  assert.throws(() => unpadPkcs(new Uint8Array([1, 3]), 2), /PKCS#7/);
  assert.throws(() => unpadPkcs(new Uint8Array([2, 3]), 2), /PKCS#7/);
  assert.throws(() => unpadPkcs(new Uint8Array([1, 2]), 2), /PKCS#7/);
});

test('noPadding requires block-aligned input and round-trips aligned data', () => {
  assert.throws(() => paddingsIndex.noPadding.pad(new Uint8Array([1, 2, 3]), 16), /multiple of the block size/);
  const aligned = textToBytes('1234567890123456');
  assert.deepEqual(paddingsIndex.noPadding.pad(aligned, 16), aligned);
  assert.deepEqual(paddingsIndex.noPadding.unpad(aligned, 16), aligned);
});

test('ansi-x923 pad produces zero-filled padding bytes', () => {
  assert.equal(bytesToHex(paddingsIndex.ansiX923.pad(textToBytes('abc'), 16)), '6162630000000000000000000000000d');
});

test('iso97971 pad appends 0x80 marker', () => {
  assert.equal(bytesToHex(paddingsIndex.iso97971.pad(textToBytes('abc'), 4)), '61626380');
});

test('zero padding leaves aligned input unchanged', () => {
  assert.deepEqual(paddingsIndex.zeroPadding.pad(textToBytes('abcd'), 4), textToBytes('abcd'));
  assert.deepEqual(paddingsIndex.zeroPadding.unpad(new Uint8Array([0x61, 0x62, 0x63, 0x64, 0, 0]), 4), textToBytes('abcd'));
});

test('paddings preset exposes all padding components', () => {
  assert.deepEqual(
    [...paddingsPreset().components()].map((component) => component.name),
    ['pkcs7', 'pkcs5', 'none', 'ansi-x923', 'iso10126', 'iso97971', 'zero'],
  );
});

test('individual padding presets expose their component', () => {
  assert.equal([...pkcs7Preset.components()][0].name, 'Pkcs7');
  assert.equal([...pkcs5Preset.components()][0].name, 'Pkcs5');
  assert.equal([...noPaddingPreset.components()][0].name, 'NoPadding');
  assert.equal([...ansiX923Preset.components()][0].name, 'AnsiX923');
  assert.equal([...iso10126Preset.components()][0].name, 'Iso10126');
  assert.equal([...iso97971Preset.components()][0].name, 'Iso97971');
  assert.equal([...zeroPaddingPreset.components()][0].name, 'ZeroPadding');
});

test('index re-exports padding components and preset', () => {
  assert.equal(paddingsIndex.pkcs7.name, 'Pkcs7');
  assert.equal(paddingsIndex.pkcs5.name, 'Pkcs5');
  assert.equal(paddingsIndex.noPadding.name, 'NoPadding');
  assert.equal(paddingsIndex.ansiX923.name, 'AnsiX923');
  assert.equal(paddingsIndex.iso10126.name, 'Iso10126');
  assert.equal(paddingsIndex.iso97971.name, 'Iso97971');
  assert.equal(paddingsIndex.zeroPadding.name, 'ZeroPadding');
  assert.equal(typeof paddingsIndex.paddingsPreset, 'function');
});
