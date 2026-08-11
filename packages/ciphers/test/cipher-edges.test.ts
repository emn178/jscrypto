import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { AeadCreateContext, BlockCipher } from '@jscrypto/core';
import { createRegistry } from '@jscrypto/core';
import { aesGcm } from '../src/aes.js';
import { aes } from '../src/aes-node.js';
import { decryptWithBlockOffset, encryptWithBlockOffset } from '../src/block-offset.js';
import { chacha20 } from '../src/chacha20.js';
import { createDesCipher } from '../src/des.js';
import { createTripleDesCipher } from '../src/triple-des.js';
import { hexToBytes, textToBytes } from './helpers/bytes.js';

test('AES-GCM AEAD validates empty nonce and bad tagLength', () => {
  const registry = createRegistry().use(aes).use(aesGcm);
  const aead = registry.createAead({
    algorithm: 'AES-GCM',
    key: hexToBytes('000102030405060708090a0b0c0d0e0f'),
  });
  const nonce = hexToBytes('101112131415161718191a1b');

  assert.throws(() => aead.seal(textToBytes('abc'), { nonce: new Uint8Array() }), /requires a nonce/);
  assert.throws(() => aead.seal(textToBytes('abc'), { nonce, tagLength: 3 }), /tagLength/);
  assert.throws(() => aead.seal(textToBytes('abc'), { nonce, tagLength: 3.5 }), /tagLength/);
});

test('AES-GCM opener rethrows non-authentication errors', () => {
  const key = hexToBytes('000102030405060708090a0b0c0d0e0f');
  const nonce = hexToBytes('101112131415161718191a1b');
  const context: AeadCreateContext = {
    createEncryptor() {
      return {
        process: () => new Uint8Array(0),
        finalize: () => new Uint8Array(0),
      };
    },
    createDecryptor() {
      return {
        process: () => new Uint8Array(0),
        finalize() {
          throw new Error('boom');
        },
      };
    },
    createBlockCipher() {
      throw new Error('unused');
    },
  };

  const opener = aesGcm.create({ key }, context).createOpener({ nonce });
  assert.throws(() => opener.finalize(), /boom/);
});

test('ChaCha20 rejects padding options on the raw stream cipher', () => {
  const registry = createRegistry().use(chacha20);
  assert.throws(
    () => registry.createCipher({
      cipher: 'ChaCha20',
      key: new Uint8Array(32),
      nonce: new Uint8Array(12),
      padding: 'Pkcs7',
    }).encrypt(textToBytes('x')),
    /does not support padding/,
  );
});

test('DES raw block API validates input and output lengths', () => {
  const cipher = createDesCipher(hexToBytes('133457799bbcdff1'));
  assert.throws(() => cipher.encrypt(new Uint8Array(7), new Uint8Array(7)), /multiple of 64 bits/);
  assert.throws(() => cipher.decrypt(new Uint8Array(8), new Uint8Array(7)), /output length/);
});

test('TripleDES raw block API validates input and output lengths', () => {
  const cipher = createTripleDesCipher(hexToBytes('0123456789abcdeffedcba9876543210'));
  assert.throws(() => cipher.encrypt(new Uint8Array(7), new Uint8Array(7)), /multiple of 64 bits/);
  assert.throws(() => cipher.decrypt(new Uint8Array(8), new Uint8Array(7)), /output length/);
});

test('block-offset helpers support ciphers without encryptBlock hooks', () => {
  const input = new Uint8Array(8).fill(1);
  const output = new Uint8Array(16);
  const cipher: BlockCipher = {
    blockSize: 8,
    encrypt(src, dest) {
      dest.set(src);
      return dest;
    },
    decrypt(src, dest) {
      dest.set(src);
      return dest;
    },
  };

  encryptWithBlockOffset(cipher, input, 0, output, 0);
  decryptWithBlockOffset(cipher, output, 0, output, 8);
  assert.deepEqual(output.subarray(0, 8), input);
  assert.deepEqual(output.subarray(8, 16), input);
});
