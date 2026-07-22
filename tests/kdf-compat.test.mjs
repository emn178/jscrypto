import assert from 'node:assert/strict';
import { test } from 'node:test';
import { deriveEvpKdf, derivePbkdf2, evpKdf, pbkdf2 } from '@jscrypto/classic';
import {
  keccak512,
  md5,
  registerClassicHashes,
  ripemd160,
  sha1,
  sha224,
  sha256,
  sha3,
  sha384,
  sha512,
} from '@jscrypto/classic/hashes';
import { createClassicRegistry, registry as defaultRegistry } from '@jscrypto/classic';
import { bytesToHex, hexToBytes, textToBytes } from './helpers/bytes.mjs';

test('PBKDF2 matches CryptoJS upstream vectors', () => {
  const cases = [
    {
      input: 'password',
      salt: 'ATHENA.MIT.EDUraeburn',
      iterations: 250000,
      length: 16,
      expected: '62929ab995a1111c75c37bc562261ea3',
    },
    {
      input: 'password',
      salt: 'ATHENA.MIT.EDUraeburn',
      iterations: 2,
      length: 32,
      expected: '262fb72ea65b44ab5ceba7f8c8bfa7815ff9939204eb7357a59a75877d745777',
    },
    {
      input: 'password',
      salt: 'ATHENA.MIT.EDUraeburn',
      iterations: 1200,
      length: 16,
      expected: 'c76a982415f1acc71dc197273c5b6ada',
    },
    {
      input: 'password',
      salt: hexToBytes('1234567878563412'),
      iterations: 5,
      length: 32,
      expected: '74e98b2e9eeddaab3113c1efc6d82b073c4860195b3e0737fa21a4778f376321',
    },
  ];

  for (const item of cases) {
    const derived = derivePbkdf2({
      input: item.input,
      salt: item.salt,
      iterations: item.iterations,
      length: item.length,
      hash: sha256,
    });
    assert.equal(bytesToHex(derived), item.expected);
  }
});

test('classic registries require opt-in hash registration', () => {
  assert.equal(defaultRegistry.list('hash').length, 0);
  const registry = createClassicRegistry();
  assert.throws(() => registry.createPassphraseCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    passphrase: 'secret',
    kdf: 'EvpKDF',
    salt: new Uint8Array(8),
  }).encrypt(new Uint8Array()), /Hash not registered: MD5/);

  registerClassicHashes(registry);
  registerClassicHashes(registry);
  assert.equal(registry.getHash('sha-256').name, 'SHA256');
  assert.equal(registry.getHash('SHA256').name, 'SHA256');
  assert.equal(registry.getHash('KECCAK512'), keccak512);
  assert.equal(registry.getHash('SHA3'), sha3);
});

test('PBKDF2 component resolves its registered default hash', () => {
  const registry = registerClassicHashes(createClassicRegistry());
  const derived = pbkdf2.derive({
    input: 'password',
    salt: 'ATHENA.MIT.EDUraeburn',
    iterations: 250000,
    length: 16,
  }, {
    getHash: registry.getHash.bind(registry),
  });

  assert.equal(bytesToHex(derived), '62929ab995a1111c75c37bc562261ea3');
});

test('EvpKDF matches CryptoJS upstream vector', () => {
  const derived = deriveEvpKdf({
    input: 'password',
    salt: 'saltsalt',
    length: 48,
      hash: md5,
  });

  assert.equal(
    bytesToHex(derived),
    'fdbdf3419fff98bdb0241390f62a9db35f4aba29d77566377997314ebfc709f20b5ca7b1081f94b1ac12e3c8ba87d05a',
  );
});

test('EvpKDF component resolves its registered default hash', () => {
  const registry = registerClassicHashes(createClassicRegistry());
  const derived = evpKdf.derive({
    input: 'password',
    salt: 'saltsalt',
    length: 48,
  }, {
    getHash: registry.getHash.bind(registry),
  });

  assert.equal(
    bytesToHex(derived),
    'fdbdf3419fff98bdb0241390f62a9db35f4aba29d77566377997314ebfc709f20b5ca7b1081f94b1ac12e3c8ba87d05a',
  );
});

test('RIPEMD160 matches standard digest vectors', () => {
  const cases = [
    ['', '9c1185a5c5e9fc54612808977ee8f548b2258d31'],
    ['a', '0bdc9d2d256b3ee9daae347be6f4dc835a467ffe'],
    ['abc', '8eb208f7e05d987a9b044a8e98c6b087f15a0bfc'],
    ['message digest', '5d0689ef49d2fae572b881b123a85ffa21595f36'],
    ['abcdefghijklmnopqrstuvwxyz', 'f71c27109c692c1b56bbdceb5b9d2865b3708dbc'],
    [
      'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
      '12a053384a9c0c88e405a06c27dcf49ada62eb2b',
    ],
    [
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
      'b0e20b6e3116640286ed3a87a5713079b21f5189',
    ],
  ];

  for (const [input, expected] of cases) {
    assert.equal(bytesToHex(ripemd160.hash(textToBytes(input))), expected);
  }
});

test('KDFs match permanent CryptoJS vectors for every classic hash', () => {
  const cases = [
    [md5, '3d4a8d4fb4c6e8686b21d361429029', 'b51daa690c78633427a9fcac3db8a1'],
    [sha1, 'e3a8dfcf2eea6dc81d2ad154274faa', '59d86eb82797eb0fa6622ca84d2009'],
    [sha224, '039e5f55e4889f2fa3b00abbc647a0', '361229e591eb3940fd1caca59f3970'],
    [sha256, '433c26cdaee1e0228707d88152f8cf', '8f45ebd930d419bd84c40a8713d738'],
    [sha384, '23fee816811e5c5b8894553a432319', '86ad37ab5c5d4370a2da3ee67d2c7c'],
    [sha512, '5560590d63c40751fbf7c2d1db259d', '2d1059f379348cbabab4ba06d4d4e0'],
    [keccak512, '92a6eb6a8c6f46b7f61e0d19543e9a', '1160862c6cb64adb3515097233c149'],
    [sha3, '92a6eb6a8c6f46b7f61e0d19543e9a', '1160862c6cb64adb3515097233c149'],
    [ripemd160, '387abab580b1b919e8f997a3802914', '9c226abf62735dbdeff154e21d2170'],
  ];

  for (const [hash, evpExpected, pbkdf2Expected] of cases) {
    assert.equal(bytesToHex(deriveEvpKdf({
      input: 'password',
      salt: 'saltsalt',
      iterations: 2,
      length: 15,
      hash,
    })), evpExpected);
    assert.equal(bytesToHex(derivePbkdf2({
      input: 'password',
      salt: 'saltsalt',
      iterations: 2,
      length: 15,
      hash,
    })), pbkdf2Expected);
  }
});
