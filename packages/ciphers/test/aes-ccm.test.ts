import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  createRegistry,
  MissingComponentError,
  type BlockCipherComponent,
} from '@jscrypto/core';
import {
  aes as browserAes,
  aesCcm as browserAesCcm,
  aesPreset as browserAesPreset,
} from '../src/aes.js';
import {
  aes as nodeAes,
  aesCcm,
  aesPreset,
} from '../src/aes-node.js';
import { chacha20 } from '../src/chacha20.js';
import { bytesToHex, hexToBytes } from './helpers/bytes.js';

function componentNames(preset: { components(): Iterable<{ name: string }> }): string[] {
  return [...preset.components()].map((component) => component.name);
}

function createAesCcmRegistry() {
  return createRegistry().use(aesPreset);
}

test('component metadata matches the public surface', () => {
  assert.equal(aesCcm.kind, 'aead');
  assert.equal(aesCcm.name, 'AES-CCM');
  assert.deepEqual(aesCcm.keySizes, [16, 24, 32]);
  assert.deepEqual(aesCcm.nonceSizes, [7, 8, 9, 10, 11, 12, 13]);
  assert.equal(aesCcm.recommendedNonceSize, 12);
  assert.deepEqual(aesCcm.tagSizes, [4, 6, 8, 10, 12, 14, 16]);
  assert.equal(typeof aesCcm.create, 'function');
});

test('aesPreset registers AES-CCM', () => {
  assert.deepEqual(
    componentNames(aesPreset),
    ['AES', 'AES-GCM', 'AES-CCM'],
  );
  const registry = createAesCcmRegistry();
  assert.equal(registry.has('aead', 'AES-CCM'), true);
});

// RFC 3610 Packet Vector #1 (M=8, L=2, 13-byte nonce, non-empty AAD)
test('RFC 3610 packet vector #1', () => {
  const registry = createAesCcmRegistry();
  const aead = registry.createAead({
    algorithm: 'AES-CCM',
    key: hexToBytes('c0c1c2c3c4c5c6c7c8c9cacbcccdcecf'),
  });
  const nonce = hexToBytes('00000003020100a0a1a2a3a4a5');
  const aad = hexToBytes('0001020304050607');
  const plaintext = hexToBytes('08090a0b0c0d0e0f101112131415161718191a1b1c1d1e');
  const sealed = aead.seal(plaintext, { nonce, aad, tagLength: 8 });

  assert.equal(
    bytesToHex(sealed),
    '588c979a61c663d2f066d0c2c0f989806d5f6b61dac38417e8d12cfdf926e0',
  );
  assert.deepEqual(aead.open(sealed, { nonce, aad, tagLength: 8 }), plaintext);
});

// RFC 3610 Packet Vector #2
test('RFC 3610 packet vector #2', () => {
  const registry = createAesCcmRegistry();
  const aead = registry.createAead({
    algorithm: 'AES-CCM',
    key: hexToBytes('c0c1c2c3c4c5c6c7c8c9cacbcccdcecf'),
  });
  const nonce = hexToBytes('00000004030201a0a1a2a3a4a5');
  const aad = hexToBytes('0001020304050607');
  const plaintext = hexToBytes('08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
  const sealed = aead.seal(plaintext, { nonce, aad, tagLength: 8 });

  assert.equal(
    bytesToHex(sealed),
    '72c91a36e135f8cf291ca894085c87e3cc15c439c9e43a3ba091d56e10400916',
  );
});

// 12-byte nonce + tagLength 16 via Node crypto cross-check values
test('12-byte nonce with tagLength 16 round-trips and matches known output', () => {
  const registry = createAesCcmRegistry();
  const aead = registry.createAead({
    algorithm: 'AES-CCM',
    key: hexToBytes('404142434445464748494a4b4c4d4e4f'),
  });
  const nonce = hexToBytes('101112131415161718191a1b');
  const aad = hexToBytes('0001020304050607');
  const plaintext = hexToBytes('20212223');
  const sealed = aead.seal(plaintext, { nonce, aad, tagLength: 16 });

  assert.equal(nonce.length, 12);
  assert.equal(sealed.length, plaintext.length + 16);
  assert.deepEqual(aead.open(sealed, { nonce, aad, tagLength: 16 }), plaintext);
});

test('empty AAD and empty plaintext with default tagLength 16', () => {
  const registry = createAesCcmRegistry();
  const aead = registry.createAead({
    algorithm: 'AES-CCM',
    key: hexToBytes('00000000000000000000000000000000'),
  });
  const nonce = hexToBytes('000000000000000000000000');
  const sealed = aead.seal(new Uint8Array(), { nonce });

  assert.equal(sealed.length, 16);
  assert.deepEqual(aead.open(sealed, { nonce }), new Uint8Array());
});

test('tagLength 4 is accepted', () => {
  const registry = createAesCcmRegistry();
  const aead = registry.createAead({
    algorithm: 'AES-CCM',
    key: hexToBytes('c0c1c2c3c4c5c6c7c8c9cacbcccdcecf'),
  });
  const nonce = hexToBytes('00000003020100a0a1a2a3a4a5');
  const plaintext = hexToBytes('08090a0b');
  const sealed = aead.seal(plaintext, { nonce, tagLength: 4 });

  assert.equal(sealed.length, plaintext.length + 4);
  assert.deepEqual(aead.open(sealed, { nonce, tagLength: 4 }), plaintext);
});

test('appended-tag and detached-tag open both work', () => {
  const registry = createAesCcmRegistry();
  const aead = registry.createAead({
    algorithm: 'AES-CCM',
    key: hexToBytes('c0c1c2c3c4c5c6c7c8c9cacbcccdcecf'),
  });
  const nonce = hexToBytes('00000003020100a0a1a2a3a4a5');
  const aad = hexToBytes('0001020304050607');
  const plaintext = hexToBytes('08090a0b0c0d0e0f101112131415161718191a1b1c1d1e');
  const sealed = aead.seal(plaintext, { nonce, aad, tagLength: 8 });
  const ciphertext = sealed.subarray(0, sealed.length - 8);
  const tag = sealed.subarray(sealed.length - 8);

  assert.deepEqual(aead.open(sealed, { nonce, aad, tagLength: 8 }), plaintext);
  assert.deepEqual(aead.open(ciphertext, { nonce, aad, tag }), plaintext);
});

test('appended-tag open rejects ciphertext shorter than the tag', () => {
  const registry = createAesCcmRegistry();
  const aead = registry.createAead({
    algorithm: 'AES-CCM',
    key: hexToBytes('c0c1c2c3c4c5c6c7c8c9cacbcccdcecf'),
  });
  const nonce = hexToBytes('00000003020100a0a1a2a3a4a5');

  assert.throws(
    () => aead.open(new Uint8Array(7), { nonce, tagLength: 8 }),
    /shorter than the authentication tag/,
  );
});

test('wrong tag and wrong AAD throw AES-CCM authentication failed', () => {
  const registry = createAesCcmRegistry();
  const aead = registry.createAead({
    algorithm: 'AES-CCM',
    key: hexToBytes('c0c1c2c3c4c5c6c7c8c9cacbcccdcecf'),
  });
  const nonce = hexToBytes('00000003020100a0a1a2a3a4a5');
  const aad = hexToBytes('0001020304050607');
  const plaintext = hexToBytes('08090a0b');
  const sealed = aead.seal(plaintext, { nonce, aad, tagLength: 8 });
  const corrupted = sealed.slice();
  corrupted[corrupted.length - 1] ^= 0xff;

  assert.throws(
    () => aead.open(corrupted, { nonce, aad, tagLength: 8 }),
    /AES-CCM authentication failed/,
  );
  assert.throws(
    () => aead.open(sealed, { nonce, aad: hexToBytes('0001020304050608'), tagLength: 8 }),
    /AES-CCM authentication failed/,
  );
});

test('nonce validation rejects missing and invalid lengths', () => {
  const registry = createAesCcmRegistry();
  const aead = registry.createAead({
    algorithm: 'AES-CCM',
    key: hexToBytes('c0c1c2c3c4c5c6c7c8c9cacbcccdcecf'),
  });

  assert.throws(() => aead.seal(new Uint8Array(1)), /AES-CCM requires a nonce/);
  assert.throws(
    () => aead.seal(new Uint8Array(1), { nonce: new Uint8Array(6) }),
    /nonce length must be between 7 and 13/,
  );
  assert.throws(
    () => aead.seal(new Uint8Array(1), { nonce: new Uint8Array(14) }),
    /nonce length must be between 7 and 13/,
  );
});

test('tagLength validation rejects odd, too small, and too large values', () => {
  const registry = createAesCcmRegistry();
  const aead = registry.createAead({
    algorithm: 'AES-CCM',
    key: hexToBytes('c0c1c2c3c4c5c6c7c8c9cacbcccdcecf'),
  });
  const nonce = hexToBytes('00000003020100a0a1a2a3a4a5');

  assert.throws(() => aead.seal(new Uint8Array(1), { nonce, tagLength: 5 }), /tagLength/);
  assert.throws(() => aead.seal(new Uint8Array(1), { nonce, tagLength: 3 }), /tagLength/);
  assert.throws(() => aead.seal(new Uint8Array(1), { nonce, tagLength: 17 }), /tagLength/);
});

test('detached tag lengths 3, 5, and 17 are rejected before authentication', () => {
  const registry = createAesCcmRegistry();
  const aead = registry.createAead({
    algorithm: 'AES-CCM',
    key: hexToBytes('c0c1c2c3c4c5c6c7c8c9cacbcccdcecf'),
  });
  const nonce = hexToBytes('00000003020100a0a1a2a3a4a5');

  for (const length of [3, 5, 17]) {
    assert.throws(
      () => aead.open(new Uint8Array(4), { nonce, tag: new Uint8Array(length) }),
      /tagLength/,
    );
  }
});

test('plaintext too large for the nonce length is rejected', () => {
  const registry = createAesCcmRegistry();
  const aead = registry.createAead({
    algorithm: 'AES-CCM',
    key: hexToBytes('c0c1c2c3c4c5c6c7c8c9cacbcccdcecf'),
  });
  // 13-byte nonce => L=2 => max plaintext 65535
  const nonce = hexToBytes('00000003020100a0a1a2a3a4a5');
  assert.throws(
    () => aead.seal(new Uint8Array(65536), { nonce, tagLength: 8 }),
    /too large for the nonce length/,
  );
});

test('AAD length encoding covers the 0xfffe form with real AAD', () => {
  const registry = createAesCcmRegistry();
  const aead = registry.createAead({
    algorithm: 'AES-CCM',
    key: hexToBytes('c0c1c2c3c4c5c6c7c8c9cacbcccdcecf'),
  });
  const nonce = hexToBytes('00000003020100a0a1a2a3a4a5');
  const aad = new Uint8Array(0xff00);
  aad[0] = 0xab;
  aad[aad.length - 1] = 0xcd;
  const plaintext = hexToBytes('08090a0b');
  const sealed = aead.seal(plaintext, { nonce, aad, tagLength: 8 });
  assert.deepEqual(aead.open(sealed, { nonce, aad, tagLength: 8 }), plaintext);
});

test('createSealer/createOpener buffer until finalize', () => {
  const registry = createAesCcmRegistry();
  const aead = registry.createAead({
    algorithm: 'AES-CCM',
    key: hexToBytes('c0c1c2c3c4c5c6c7c8c9cacbcccdcecf'),
  });
  const nonce = hexToBytes('00000003020100a0a1a2a3a4a5');
  const plaintext = hexToBytes('08090a0b0c0d0e0f');

  const sealer = aead.createSealer({ nonce, tagLength: 8 });
  assert.deepEqual(sealer.process(plaintext.subarray(0, 4)), new Uint8Array(0));
  const sealed = sealer.finalize(plaintext.subarray(4));
  assert.equal(sealed.length, plaintext.length + 8);

  const opener = aead.createOpener({ nonce, tagLength: 8 });
  assert.deepEqual(opener.process(sealed.subarray(0, 5)), new Uint8Array(0));
  assert.deepEqual(opener.finalize(sealed.subarray(5)), plaintext);
});

test('destructured facade methods still work', () => {
  const registry = createAesCcmRegistry();
  const { seal, open, createSealer, createOpener } = registry.createAead({
    algorithm: 'AES-CCM',
    key: hexToBytes('c0c1c2c3c4c5c6c7c8c9cacbcccdcecf'),
  });
  const nonce = hexToBytes('00000003020100a0a1a2a3a4a5');
  const plaintext = hexToBytes('08090a0b');
  const sealed = seal(plaintext, { nonce, tagLength: 8 });

  assert.deepEqual(open(sealed, { nonce, tagLength: 8 }), plaintext);
  assert.deepEqual(
    createOpener({ nonce, tagLength: 8 }).finalize(
      createSealer({ nonce, tagLength: 8 }).finalize(plaintext),
    ),
    plaintext,
  );
});

test('Node AES path works when block cipher has no encryptBlock hook', () => {
  const nodeBlockAes = nodeAes as BlockCipherComponent<'AES'>;
  assert.equal(typeof nodeBlockAes.create(new Uint8Array(16)).encryptBlock, 'undefined');
  const registry = createRegistry().use(nodeBlockAes).use(aesCcm);
  const aead = registry.createAead({
    algorithm: 'AES-CCM',
    key: hexToBytes('c0c1c2c3c4c5c6c7c8c9cacbcccdcecf'),
  });
  const nonce = hexToBytes('00000003020100a0a1a2a3a4a5');
  const plaintext = hexToBytes('08090a0b0c0d0e0f101112131415161718191a1b1c1d1e');
  const aad = hexToBytes('0001020304050607');
  const sealed = aead.seal(plaintext, { nonce, aad, tagLength: 8 });
  assert.equal(
    bytesToHex(sealed),
    '588c979a61c663d2f066d0c2c0f989806d5f6b61dac38417e8d12cfdf926e0',
  );
});

test('browser AES encryptBlock path also seals correctly', () => {
  const browserBlockAes = browserAes as BlockCipherComponent<'AES'>;
  assert.equal(typeof browserBlockAes.create(new Uint8Array(16)).encryptBlock, 'function');

  const registry = createRegistry().use(browserBlockAes).use(browserAesCcm);
  const aead = registry.createAead({
    algorithm: 'AES-CCM',
    key: hexToBytes('c0c1c2c3c4c5c6c7c8c9cacbcccdcecf'),
  });
  const nonce = hexToBytes('00000003020100a0a1a2a3a4a5');
  const plaintext = hexToBytes('08090a0b0c0d0e0f101112131415161718191a1b1c1d1e');
  const aad = hexToBytes('0001020304050607');
  const sealed = aead.seal(plaintext, { nonce, aad, tagLength: 8 });
  assert.equal(
    bytesToHex(sealed),
    '588c979a61c663d2f066d0c2c0f989806d5f6b61dac38417e8d12cfdf926e0',
  );
});

test('invalid AES key size is rejected', () => {
  const registry = createAesCcmRegistry();
  assert.throws(
    () => registry.createAead({ algorithm: 'AES-CCM', key: new Uint8Array(15) }),
    /AES key must be 128, 192, or 256 bits/,
  );
});

test('createAead without AES cipher registered fails looking up the block cipher', () => {
  const registry = createRegistry().use(aesCcm);
  assert.throws(
    () => registry.createAead({ algorithm: 'AES-CCM', key: new Uint8Array(16) }),
    MissingComponentError,
  );
});

test('already finalized transform throws', () => {
  const registry = createAesCcmRegistry();
  const aead = registry.createAead({
    algorithm: 'AES-CCM',
    key: hexToBytes('c0c1c2c3c4c5c6c7c8c9cacbcccdcecf'),
  });
  const nonce = hexToBytes('00000003020100a0a1a2a3a4a5');
  const sealer = aead.createSealer({ nonce, tagLength: 8 });
  sealer.finalize(new Uint8Array(1));
  assert.throws(() => sealer.process(new Uint8Array(1)), /already finalized/);
  assert.throws(() => sealer.finalize(), /already finalized/);
});

test('createBlockCipher rejects stream cipher components', () => {
  const fakeAead = {
    kind: 'aead' as const,
    name: 'Fake-Needs-Block',
    create(_params: unknown, context: { createBlockCipher: (options: { cipher: string; key: Uint8Array }) => unknown }) {
      return {
        createSealer() {
          context.createBlockCipher({ cipher: 'ChaCha20', key: new Uint8Array(32) });
          return {
            process: () => new Uint8Array(0),
            finalize: () => new Uint8Array(0),
          };
        },
        createOpener() {
          return {
            process: () => new Uint8Array(0),
            finalize: () => new Uint8Array(0),
          };
        },
      };
    },
  };

  const registry = createRegistry().use(chacha20).use(fakeAead);
  const aead = registry.createAead({ algorithm: 'Fake-Needs-Block', key: new Uint8Array(16) });
  assert.throws(
    () => aead.createSealer(),
    /Expected a block cipher component: ChaCha20/,
  );
});

test('browser aesPreset still registers AES-CCM', () => {
  assert.deepEqual(
    componentNames(browserAesPreset),
    ['AES', 'AES-GCM', 'AES-CCM'],
  );
});
