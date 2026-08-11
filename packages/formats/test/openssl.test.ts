import assert from 'node:assert/strict';
import { test } from 'node:test';
import { OPENSSL_SALTED_MAGIC, opensslFormat, opensslPreset } from '../src/openssl.js';
import { formatsPreset } from '../src/preset.js';
import * as index from '../src/index.js';
import { bytesToHex, hexToBytes } from './helpers/bytes.js';

test('OpenSSL format stringifies salted bytes', () => {
  const format = opensslFormat;
  const ciphertext = hexToBytes('000102030405060708090a0b0c0d0e0f');
  const salt = hexToBytes('0123456789abcdef');
  const output = format.stringify({ ciphertext, salt });

  assert.equal(bytesToHex(output), `${bytesToHex(OPENSSL_SALTED_MAGIC)}0123456789abcdef000102030405060708090a0b0c0d0e0f`);
});

test('OpenSSL format stringifies unsalted bytes', () => {
  const format = opensslFormat;
  const ciphertext = hexToBytes('000102030405060708090a0b0c0d0e0f');

  assert.deepEqual(format.stringify({ ciphertext }), ciphertext);
});

test('OpenSSL format parses salted bytes', () => {
  const format = opensslFormat;
  const input = hexToBytes(`${bytesToHex(OPENSSL_SALTED_MAGIC)}0123456789abcdef000102030405060708090a0b0c0d0e0f`);
  const parsed = format.parse(input);

  assert.equal(bytesToHex(parsed.salt ?? new Uint8Array()), '0123456789abcdef');
  assert.equal(bytesToHex(parsed.ciphertext), '000102030405060708090a0b0c0d0e0f');
});

test('OpenSSL format parses unsalted bytes', () => {
  const format = opensslFormat;
  const input = hexToBytes('000102030405060708090a0b0c0d0e0f');
  const parsed = format.parse(input);

  assert.equal(parsed.salt, undefined);
  assert.equal(bytesToHex(parsed.ciphertext), '000102030405060708090a0b0c0d0e0f');
});

test('OpenSSL format rejects invalid salt length', () => {
  const format = opensslFormat;

  assert.throws(() => format.stringify({
    ciphertext: new Uint8Array(),
    salt: new Uint8Array([1, 2, 3]),
  }), /64 bits/);
});

test('opensslPreset exposes the OpenSSL format component', () => {
  assert.deepEqual([...index.opensslPreset.components()], [opensslFormat]);
  assert.deepEqual([...opensslPreset.components()], [opensslFormat]);
});

test('formats preset and index re-export OpenSSL format', () => {
  assert.equal([...formatsPreset().components()][0]?.name, 'openssl');
  assert.equal(index.opensslFormat.name, 'OpenSSL');
  assert.equal(index.formatsPreset().name, 'formats');
  assert.deepEqual(index.OPENSSL_SALTED_MAGIC, OPENSSL_SALTED_MAGIC);
});
