import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createRegistry } from '@jscrypto/core';
import { md5, sha256 } from '@jscrypto/hashes';
import { deriveEvpKdf } from '../src/evpkdf.js';
import { argon2Preset } from '../src/argon2.js';
import { derivePbkdf2 as derivePbkdf2Direct } from '../src/pbkdf2.js';
import { deriveScrypt } from '../src/scrypt.js';
import { deriveArgon2 } from '../src/argon2.js';

test('EvpKDF rejects missing input and accepts iterations', () => {
  assert.throws(
    () => deriveEvpKdf({ salt: 's', length: 16, hash: md5 } as Parameters<typeof deriveEvpKdf>[0]),
    /EvpKDF requires input\./,
  );
  assert.throws(
    () => deriveEvpKdf({ input: null, salt: 's', length: 16, hash: md5 } as unknown as Parameters<typeof deriveEvpKdf>[0]),
    /EvpKDF requires input\./,
  );
  const withIterations = deriveEvpKdf({
    input: new TextEncoder().encode('password'),
    salt: new TextEncoder().encode('saltsalt'),
    iterations: 2,
    length: 16,
    hash: md5,
  });
  assert.equal(withIterations.length, 16);
});

test('PBKDF2 rejects missing input', () => {
  assert.throws(
    () => derivePbkdf2Direct({ salt: 's', iterations: 1, length: 16, hash: sha256 } as Parameters<typeof derivePbkdf2Direct>[0]),
    /PBKDF2 requires input\./,
  );
  assert.throws(
    () => derivePbkdf2Direct({ input: null, salt: 's', iterations: 1, length: 16, hash: sha256 } as unknown as Parameters<typeof derivePbkdf2Direct>[0]),
    /PBKDF2 requires input\./,
  );
});

test('Scrypt rejects missing input and salt and accepts maxmem', () => {
  assert.throws(
    () => deriveScrypt({ salt: 'NaCl', N: 1024, r: 8, p: 1, length: 32 } as Parameters<typeof deriveScrypt>[0]),
    /Scrypt requires input\./,
  );
  assert.throws(
    () => deriveScrypt({ input: 'password', N: 1024, r: 8, p: 1, length: 32 } as Parameters<typeof deriveScrypt>[0]),
    /Scrypt requires salt\./,
  );
  assert.throws(
    () => deriveScrypt({ input: 'password', salt: 'NaCl', N: 1024, r: 0, p: 1, length: 32 }),
    /Scrypt r must be a positive integer/,
  );
  assert.throws(
    () => deriveScrypt({ input: 'password', salt: 'NaCl', N: 1024, r: 8, p: 1, length: 32, maxmem: 0 }),
    /Scrypt maxmem must be a positive integer/,
  );
  const derived = deriveScrypt({
    input: new TextEncoder().encode('password'),
    salt: new TextEncoder().encode('NaCl'),
    N: 1024,
    r: 8,
    p: 16,
    length: 64,
    maxmem: 128 * 1024 * 1024,
  });
  assert.equal(derived.length, 64);
  assert.throws(() => deriveScrypt(null as unknown as Parameters<typeof deriveScrypt>[0]), /Scrypt requires params/);
});

test('Argon2 rejects missing input and salt and covers alternate modes', () => {
  assert.throws(
    () => deriveArgon2({ salt: 'somesalt', m: 16, t: 2, p: 1, length: 32 } as Parameters<typeof deriveArgon2>[0]),
    /Argon2 requires input\./,
  );
  assert.throws(
    () => deriveArgon2({ input: 'password', m: 16, t: 2, p: 1, length: 32 } as Parameters<typeof deriveArgon2>[0]),
    /Argon2 requires salt\./,
  );
  assert.throws(
    () => deriveArgon2({ input: 'password', salt: 'somesalt', m: 16, t: 0, p: 1, length: 32 }),
    /Argon2 t must be a positive integer/,
  );
  assert.throws(
    () => deriveArgon2({ input: 'password', salt: 'somesalt', m: 16, t: 2, p: 1, length: 32, maxmem: 0 }),
    /Argon2 maxmem must be a positive integer/,
  );

  const base = {
    input: 'password',
    salt: 'somesalt',
    m: 16,
    t: 2,
    p: 1,
    length: 32,
  };
  const id = deriveArgon2({ ...base, mode: 'id' });
  const i = deriveArgon2({
    ...base,
    mode: 'i',
    input: new TextEncoder().encode('password'),
    salt: new TextEncoder().encode('somesalt'),
  });
  const d = deriveArgon2({ ...base, mode: 'd' });
  assert.equal(id.length, 32);
  assert.notDeepEqual(i, id);
  assert.notDeepEqual(d, id);
  assert.throws(() => deriveArgon2(null as unknown as Parameters<typeof deriveArgon2>[0]), /Argon2 requires params/);
});

test('Argon2 component derives through registry', () => {
  const registry = createRegistry().use(argon2Preset);
  const derived = registry.derive({
    name: 'Argon2',
    input: 'password',
    salt: 'somesalt',
    mode: 'i',
    m: 16,
    t: 2,
    p: 1,
    length: 32,
  });
  assert.equal(derived.length, 32);
});
