import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  encodeCcmAad,
  encodeCcmAadLength,
  encodeCcmBinaryLength,
} from '../src/aes-ccm.js';
import { hexToBytes } from './helpers/bytes.js';

test('AAD length encoding helper covers short, 0xfffe, and 0xffff forms', () => {
  assert.deepEqual([...encodeCcmAadLength(0)], []);
  assert.deepEqual([...encodeCcmAad(hexToBytes('aabb'))], [0x00, 0x02, 0xaa, 0xbb]);
  assert.deepEqual([...encodeCcmAadLength(0x00ff)], [0x00, 0xff]);
  assert.deepEqual(
    [...encodeCcmAadLength(0xff00)],
    [0xff, 0xfe, 0x00, 0x00, 0xff, 0x00],
  );
  assert.deepEqual(
    [...encodeCcmAadLength(0xffffffff)],
    [0xff, 0xfe, 0xff, 0xff, 0xff, 0xff],
  );
  assert.deepEqual(
    [...encodeCcmAadLength(0x100000000)],
    [0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
  );
  assert.deepEqual(
    [...encodeCcmAadLength(Number.MAX_SAFE_INTEGER)],
    [0xff, 0xff, 0x00, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
  );
});

test('binary length encoding rejects values that do not fit the field width', () => {
  const out = new Uint8Array(4);
  encodeCcmBinaryLength(0xffff, 2, out, 0);
  assert.deepEqual([...out.subarray(0, 2)], [0xff, 0xff]);
  assert.throws(
    () => encodeCcmBinaryLength(0x10000, 2, out, 0),
    /too large for the nonce length/,
  );
});
