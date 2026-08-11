import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

test('generated declarations export the public AES / ChaCha20 / SPECK APIs', async () => {
  const aes = await readFile(new URL('../../packages/ciphers/dist/aes.d.ts', import.meta.url), 'utf8');
  assert.match(aes, /export declare const aes:/);
  assert.match(aes, /export declare const aesGcm:/);
  assert.match(aes, /export declare const aesCcm:/);
  assert.match(aes, /export declare const aesPreset:/);
  assert.match(aes, /export declare function createAesCipher/);

  const chacha20 = await readFile(
    new URL('../../packages/ciphers/dist/chacha20.d.ts', import.meta.url),
    'utf8',
  );
  assert.match(chacha20, /export declare const chacha20:/);
  assert.match(chacha20, /export declare const xchacha20:/);
  assert.match(chacha20, /export declare const chacha20Poly1305:\s*AeadComponent/);
  assert.match(chacha20, /export declare const xchacha20Poly1305:\s*AeadComponent/);
  assert.match(chacha20, /export declare const chacha20Preset:/);
  assert.doesNotMatch(chacha20, /export declare function encryptChaCha20/);
  assert.doesNotMatch(chacha20, /export declare function sealXChaCha20Poly1305/);
  assert.doesNotMatch(chacha20, /export declare function openXChaCha20Poly1305/);

  const speck = await readFile(
    new URL('../../packages/ciphers/dist/speck.d.ts', import.meta.url),
    'utf8',
  );
  assert.match(speck, /export type SpeckVariantName =/);
  assert.match(speck, /export declare const speck64_128:/);
  assert.match(speck, /export declare const speckPreset:/);
  assert.match(speck, /export declare const allSpeckComponents:/);
  assert.match(speck, /export declare function createSpeckCipher/);
  assert.doesNotMatch(speck, /createRegistry/);
});

test('generated declarations export the public HKDF API', async () => {
  const dts = await readFile(new URL('../../packages/kdfs/dist/hkdf.d.ts', import.meta.url), 'utf8');
  assert.match(dts, /export interface HkdfParams/);
  assert.match(dts, /export interface HkdfExtractParams/);
  assert.match(dts, /export interface HkdfExpandParams/);
  assert.match(dts, /export interface DeriveHkdfParams/);
  assert.match(dts, /export declare const hkdf:/);
  assert.match(dts, /export declare const hkdfExtract:/);
  assert.match(dts, /export declare const hkdfExpand:/);
  assert.match(dts, /export declare const hkdfPreset:/);
  assert.match(dts, /export declare function deriveHkdf/);
  assert.match(dts, /export declare function extractHkdf/);
  assert.match(dts, /export declare function expandHkdf/);
});
