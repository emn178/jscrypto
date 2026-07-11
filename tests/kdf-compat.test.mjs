import assert from 'node:assert/strict';
import { test } from 'node:test';
import { deriveEvpKdf, derivePbkdf2, evpKdf, pbkdf2 } from '@jscrypto/classic';
import { bytesToHex, hexToBytes } from './helpers/bytes.mjs';

test('PBKDF2 matches CryptoJS upstream vectors', () => {
  const cases = [
    {
      passphrase: 'password',
      salt: 'ATHENA.MIT.EDUraeburn',
      iterations: 250000,
      length: 16,
      expected: '62929ab995a1111c75c37bc562261ea3',
    },
    {
      passphrase: 'password',
      salt: 'ATHENA.MIT.EDUraeburn',
      iterations: 2,
      length: 32,
      expected: '262fb72ea65b44ab5ceba7f8c8bfa7815ff9939204eb7357a59a75877d745777',
    },
    {
      passphrase: 'password',
      salt: 'ATHENA.MIT.EDUraeburn',
      iterations: 1200,
      length: 16,
      expected: 'c76a982415f1acc71dc197273c5b6ada',
    },
    {
      passphrase: 'password',
      salt: hexToBytes('1234567878563412'),
      iterations: 5,
      length: 32,
      expected: '74e98b2e9eeddaab3113c1efc6d82b073c4860195b3e0737fa21a4778f376321',
    },
  ];

  for (const item of cases) {
    const derived = derivePbkdf2({
      passphrase: item.passphrase,
      salt: item.salt,
      iterations: item.iterations,
      length: item.length,
    });
    assert.equal(bytesToHex(derived), item.expected);
  }
});

test('PBKDF2 component delegates to typed derive function', () => {
  const derived = pbkdf2.derive({
    passphrase: 'password',
    salt: 'ATHENA.MIT.EDUraeburn',
    iterations: 250000,
    length: 16,
  });

  assert.equal(bytesToHex(derived), '62929ab995a1111c75c37bc562261ea3');
});

test('EvpKDF matches CryptoJS upstream vector', () => {
  const derived = deriveEvpKdf({
    passphrase: 'password',
    salt: 'saltsalt',
    length: 48,
  });

  assert.equal(
    bytesToHex(derived),
    'fdbdf3419fff98bdb0241390f62a9db35f4aba29d77566377997314ebfc709f20b5ca7b1081f94b1ac12e3c8ba87d05a',
  );
});

test('EvpKDF component delegates to typed derive function', () => {
  const derived = evpKdf.derive({
    passphrase: 'password',
    salt: 'saltsalt',
    length: 48,
  });

  assert.equal(
    bytesToHex(derived),
    'fdbdf3419fff98bdb0241390f62a9db35f4aba29d77566377997314ebfc709f20b5ca7b1081f94b1ac12e3c8ba87d05a',
  );
});
