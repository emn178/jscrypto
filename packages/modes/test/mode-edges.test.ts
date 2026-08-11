import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { BlockCipher } from '@jscrypto/core';
import { cbc, cfb, ctr, ecb, ofb } from '@jscrypto/modes';
import { bytesToHex } from './helpers/bytes.js';

function createBlockHookCipher(blockSize = 2): BlockCipher {
  return {
    blockSize,
    encrypt(input, output) {
      for (let index = 0; index < input.length; index++) {
        output[index] = input[index] ^ 0xff;
      }
      return output;
    },
    decrypt(input, output) {
      for (let index = 0; index < input.length; index++) {
        output[index] = input[index] ^ 0xff;
      }
      return output;
    },
    encryptBlock(input, inputOffset, output, outputOffset) {
      for (let index = 0; index < blockSize; index++) {
        output[outputOffset + index] = input[inputOffset + index] ^ 0xff;
      }
    },
    decryptBlock(input, inputOffset, output, outputOffset) {
      for (let index = 0; index < blockSize; index++) {
        output[outputOffset + index] = input[inputOffset + index] ^ 0xff;
      }
    },
  };
}

test('mode finalizers and counter carry branches are covered', () => {
  const blockCipher = {
    blockSize: 2,
    encrypt(input: Uint8Array, output: Uint8Array) {
      for (let index = 0; index < input.length; index++) {
        output[index] = input[index] ^ 0xff;
      }
      return output;
    },
    decrypt(input: Uint8Array, output: Uint8Array) {
      for (let index = 0; index < input.length; index++) {
        output[index] = input[index] ^ 0xff;
      }
      return output;
    },
  };

  assert.deepEqual(cbc.createEncryptor({ cipher: blockCipher, iv: new Uint8Array([0, 0]) }).finalize(new Uint8Array([1, 2])), new Uint8Array([254, 253]));
  assert.deepEqual(cbc.createDecryptor({ cipher: blockCipher, iv: new Uint8Array([0, 0]) }).finalize(new Uint8Array([254, 253])), new Uint8Array([1, 2]));
  assert.throws(() => cbc.createEncryptor({ cipher: blockCipher, iv: new Uint8Array([0, 0]) }).process(new Uint8Array([1])), /multiple/);
  assert.deepEqual(ecb.createEncryptor({ cipher: blockCipher }).finalize(new Uint8Array([1, 2])), new Uint8Array([254, 253]));
  assert.deepEqual(ecb.createEncryptor({ cipher: blockCipher }).finalize(), new Uint8Array());
  assert.deepEqual(ecb.createDecryptor({ cipher: blockCipher }).finalize(new Uint8Array([254, 253])), new Uint8Array([1, 2]));
  assert.deepEqual(cfb.createEncryptor({ cipher: blockCipher, iv: new Uint8Array([0, 0]) }).finalize(new Uint8Array([1, 2])), new Uint8Array([254, 253]));
  assert.deepEqual(ofb.createEncryptor({ cipher: blockCipher, iv: new Uint8Array([0, 0]) }).finalize(new Uint8Array([1])), new Uint8Array([254]));
  assert.deepEqual(ctr.createEncryptor({ cipher: blockCipher, iv: new Uint8Array([0, 0]) }).finalize(new Uint8Array([1])), new Uint8Array([254]));

  const observedCounters: string[] = [];
  const ctrCipher = {
    blockSize: 2,
    encrypt(input: Uint8Array, output: Uint8Array) {
      for (let offset = 0; offset < input.length; offset += 2) {
        observedCounters.push(bytesToHex(input.subarray(offset, offset + 2)));
        output[offset] = 0;
        output[offset + 1] = 0;
      }
      return output;
    },
    decrypt(input: Uint8Array, output: Uint8Array) {
      output.set(input);
      return output;
    },
  };
  ctr.createEncryptor({ cipher: ctrCipher, iv: new Uint8Array([0xff, 0xff]) }).process(new Uint8Array(3));
  assert.deepEqual(observedCounters, ['ffff', '0000']);
  observedCounters.length = 0;
  ctr.createEncryptor({ cipher: ctrCipher, iv: new Uint8Array([0, 0]) }).process(new Uint8Array(1));
  assert.deepEqual(observedCounters, ['0000']);
});

test('block-hook ciphers exercise encryptBlock and decryptBlock fast paths', () => {
  const cipher = createBlockHookCipher();
  const iv = new Uint8Array([0, 0]);
  const input = new Uint8Array([1, 2, 3, 4]);

  const encryptedCbc = cbc.createEncryptor({ cipher, iv }).process(input);
  assert.deepEqual(cbc.createDecryptor({ cipher, iv }).process(encryptedCbc), input);

  const encryptedEcb = ecb.createEncryptor({ cipher }).process(input);
  assert.deepEqual(ecb.createDecryptor({ cipher }).process(encryptedEcb), input);

  const encryptedCfb = cfb.createEncryptor({ cipher, iv: iv.slice() }).process(input);
  assert.deepEqual(cfb.createDecryptor({ cipher, iv: iv.slice() }).process(encryptedCfb), input);

  const encryptedOfb = ofb.createEncryptor({ cipher, iv: iv.slice() }).process(input);
  assert.deepEqual(ofb.createDecryptor({ cipher, iv: iv.slice() }).process(encryptedOfb), input);

  const encryptedCtr = ctr.createEncryptor({ cipher, iv: iv.slice() }).process(input);
  assert.deepEqual(ctr.createDecryptor({ cipher, iv: iv.slice() }).process(encryptedCtr), input);
});

test('CFB and OFB carry partial keystream blocks across process calls', () => {
  const cipher = createBlockHookCipher();
  const iv = new Uint8Array([0, 0]);
  const cfbEncryptor = cfb.createEncryptor({ cipher, iv: iv.slice() });
  const cfbDecryptor = cfb.createDecryptor({ cipher, iv: iv.slice() });
  const cfbInput = new Uint8Array([1, 2, 3]);
  const cfbCiphertext = new Uint8Array([
    ...cfbEncryptor.process(cfbInput.subarray(0, 1)),
    ...cfbEncryptor.process(cfbInput.subarray(1)),
  ]);
  assert.deepEqual(
    new Uint8Array([
      ...cfbDecryptor.process(cfbCiphertext.subarray(0, 1)),
      ...cfbDecryptor.process(cfbCiphertext.subarray(1)),
    ]),
    cfbInput,
  );

  const ofbEncryptor = ofb.createEncryptor({ cipher, iv: iv.slice() });
  const ofbDecryptor = ofb.createDecryptor({ cipher, iv: iv.slice() });
  const ofbInput = new Uint8Array([1, 2, 3, 4, 5]);
  const ofbCiphertext = new Uint8Array([
    ...ofbEncryptor.process(ofbInput.subarray(0, 1)),
    ...ofbEncryptor.process(ofbInput.subarray(1)),
  ]);
  assert.deepEqual(
    new Uint8Array([
      ...ofbDecryptor.process(ofbCiphertext.subarray(0, 2)),
      ...ofbDecryptor.process(ofbCiphertext.subarray(2)),
    ]),
    ofbInput,
  );
});
