import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { test } from 'node:test';
import { createRegistry } from '@jscrypto/core';
import { createClassicRegistry } from './helpers/classic-registry.mjs';
import { classicHashesPreset, sha1, sha256 } from '@jscrypto/hashes';
import {
  deriveHkdf,
  expandHkdf,
  extractHkdf,
  hkdf,
  hkdfExpand,
  hkdfExtract,
  hkdfPreset,
} from '../packages/kdfs/dist/hkdf.mjs';

const require = createRequire(import.meta.url);

function hex(value) {
  return Uint8Array.from(Buffer.from(value, 'hex'));
}

function toHex(bytes) {
  return Buffer.from(bytes).toString('hex');
}

function createHkdfRegistry() {
  return createRegistry()
    .useHash(sha256)
    .useHash(sha1)
    .use(hkdfPreset);
}

const rfc5869 = [
  {
    name: 'case 1 SHA-256',
    hash: sha256,
    hashName: 'SHA256',
    ikm: '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
    salt: '000102030405060708090a0b0c',
    info: 'f0f1f2f3f4f5f6f7f8f9',
    length: 42,
    prk: '077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5',
    okm: '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
  },
  {
    name: 'case 2 SHA-256 longer inputs',
    hash: sha256,
    hashName: 'SHA256',
    ikm: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f',
    salt: '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf',
    info: 'b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
    length: 82,
    prk: '06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244',
    okm: 'b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87',
  },
  {
    name: 'case 3 SHA-256 zero-length salt/info',
    hash: sha256,
    hashName: 'SHA256',
    ikm: '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
    salt: '',
    info: '',
    length: 42,
    prk: '19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04',
    okm: '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8',
  },
  {
    name: 'case 4 SHA-1',
    hash: sha1,
    hashName: 'SHA1',
    ikm: '0b0b0b0b0b0b0b0b0b0b0b',
    salt: '000102030405060708090a0b0c',
    info: 'f0f1f2f3f4f5f6f7f8f9',
    length: 42,
    prk: '9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243',
    okm: '085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896',
  },
  {
    name: 'case 5 SHA-1 longer inputs',
    hash: sha1,
    hashName: 'SHA1',
    ikm: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f',
    salt: '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf',
    info: 'b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
    length: 82,
    prk: '8adae09a2a307059478d309b26c4115a224cfaf6',
    okm: '0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e927336d0441f4c4300e2cff0d0900b52d3b4',
  },
  {
    name: 'case 6 SHA-1 zero-length salt/info',
    hash: sha1,
    hashName: 'SHA1',
    ikm: '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
    salt: '',
    info: '',
    length: 42,
    prk: 'da8c8a73c7fa77288ec6f5e7c297786aa0d32d01',
    okm: '0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918',
  },
  {
    name: 'case 7 SHA-1 omitted salt defaults to HashLen zeros',
    hash: sha1,
    hashName: 'SHA1',
    ikm: '0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c',
    salt: undefined,
    info: '',
    length: 42,
    prk: '2adccada18779e7c2077ad2eb19d3f3e731385dd',
    okm: '2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48',
  },
];

function vectorSalt(salt) {
  if (salt === undefined) {
    return undefined;
  }
  return salt === '' ? new Uint8Array(0) : hex(salt);
}

function vectorInfo(info) {
  return info === '' ? new Uint8Array(0) : hex(info);
}

test('deriveHkdf matches RFC 5869 vectors', () => {
  for (const vector of rfc5869) {
    const okm = deriveHkdf({
      input: hex(vector.ikm),
      salt: vectorSalt(vector.salt),
      info: vectorInfo(vector.info),
      hash: vector.hash,
      length: vector.length,
    });
    assert.equal(toHex(okm), vector.okm, vector.name);
  }
});

test('extractHkdf matches RFC 5869 PRK values', () => {
  for (const vector of rfc5869) {
    const prk = extractHkdf({
      input: hex(vector.ikm),
      salt: vectorSalt(vector.salt),
      hash: vector.hash,
    });
    assert.equal(toHex(prk), vector.prk, vector.name);
  }
});

test('expandHkdf matches RFC 5869 OKM values from Extract PRK', () => {
  for (const vector of rfc5869) {
    const okm = expandHkdf({
      input: hex(vector.prk),
      info: vectorInfo(vector.info),
      hash: vector.hash,
      length: vector.length,
    });
    assert.equal(toHex(okm), vector.okm, vector.name);
  }
});

test('registry.derive resolves registered hash names for RFC vectors', () => {
  const registry = createHkdfRegistry();
  for (const vector of rfc5869) {
    const okm = registry.derive({
      name: 'HKDF',
      input: hex(vector.ikm),
      salt: vectorSalt(vector.salt),
      info: vectorInfo(vector.info),
      hash: vector.hashName,
      length: vector.length,
    });
    assert.equal(toHex(okm), vector.okm, vector.name);

    const prk = registry.derive({
      name: 'HKDF-Extract',
      input: hex(vector.ikm),
      salt: vectorSalt(vector.salt),
      hash: vector.hashName,
    });
    assert.equal(toHex(prk), vector.prk, `${vector.name} extract`);

    const expanded = registry.derive({
      name: 'HKDF-Expand',
      input: hex(vector.prk),
      info: vectorInfo(vector.info),
      hash: vector.hashName,
      length: vector.length,
    });
    assert.equal(toHex(expanded), vector.okm, `${vector.name} expand`);
  }
});

test('hkdfPreset registers all three HKDF KDF components', () => {
  const registry = createRegistry().use(hkdfPreset);
  assert.equal(registry.has('kdf', 'HKDF'), true);
  assert.equal(registry.has('kdf', 'HKDF-Extract'), true);
  assert.equal(registry.has('kdf', 'HKDF-Expand'), true);
  assert.equal(hkdf.kind, 'kdf');
  assert.equal(hkdf.name, 'HKDF');
  assert.equal(hkdfExtract.name, 'HKDF-Extract');
  assert.equal(hkdfExpand.name, 'HKDF-Expand');
  assert.equal(hkdfPreset.kind, 'preset');
  assert.equal(hkdfPreset.name, 'hkdf');
  assert.deepEqual([...hkdfPreset.components()], [hkdf, hkdfExtract, hkdfExpand]);
});

test('omitted salt/info match empty values, and string inputs use UTF-8', () => {
  const withOmitted = deriveHkdf({
    input: 'ikm-secret',
    hash: sha256,
    length: 16,
  });
  const withEmpty = deriveHkdf({
    input: 'ikm-secret',
    salt: '',
    info: '',
    hash: sha256,
    length: 16,
  });
  const withEmptyBytes = deriveHkdf({
    input: new TextEncoder().encode('ikm-secret'),
    salt: new Uint8Array(0),
    info: new Uint8Array(0),
    hash: sha256,
    length: 16,
  });

  assert.deepEqual(withOmitted, withEmpty);
  assert.deepEqual(withOmitted, withEmptyBytes);

  const expandOmitted = expandHkdf({
    input: hex('077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5'),
    hash: sha256,
    length: 16,
  });
  const expandEmpty = expandHkdf({
    input: hex('077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5'),
    info: '',
    hash: sha256,
    length: 16,
  });
  assert.deepEqual(expandOmitted, expandEmpty);
});

test('length 0 returns empty bytes', () => {
  const okm = deriveHkdf({
    input: hex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'),
    hash: sha256,
    length: 0,
  });
  assert.deepEqual(okm, new Uint8Array(0));
  assert.deepEqual(expandHkdf({
    input: hex('077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5'),
    hash: sha256,
    length: 0,
  }), new Uint8Array(0));
});

test('HKDF-Extract does not require length', () => {
  const registry = createHkdfRegistry();
  const prk = registry.derive({
    name: 'HKDF-Extract',
    input: hex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'),
    salt: hex('000102030405060708090a0b0c'),
    hash: 'SHA256',
  });
  assert.equal(toHex(prk), '077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5');
});

test('validation rejects missing or invalid params', () => {
  const registry = createHkdfRegistry();

  assert.throws(
    () => deriveHkdf(/** @type {any} */ ({ hash: sha256, length: 16 })),
    /HKDF requires input\./,
  );
  assert.throws(
    () => deriveHkdf(/** @type {any} */ ({ input: null, hash: sha256, length: 16 })),
    /HKDF requires input\./,
  );
  assert.throws(
    () => deriveHkdf(/** @type {any} */ ({ input: hex('0b'), hash: null, length: 16 })),
    /HKDF requires hash\./,
  );
  assert.throws(
    () => deriveHkdf(/** @type {any} */ ({ input: hex('0b'), hash: undefined, length: 16 })),
    /HKDF requires hash\./,
  );
  assert.throws(
    () => deriveHkdf({ input: /** @type {any} */ (123), hash: sha256, length: 16 }),
    /HKDF input must be a Uint8Array or string\./,
  );
  assert.throws(
    () => deriveHkdf({ input: hex('0b'), salt: /** @type {any} */ (1), hash: sha256, length: 16 }),
    /HKDF salt must be a Uint8Array or string\./,
  );
  assert.throws(
    () => deriveHkdf({ input: hex('0b'), info: /** @type {any} */ ({}), hash: sha256, length: 16 }),
    /HKDF info must be a Uint8Array or string\./,
  );
  assert.throws(
    () => deriveHkdf({ input: hex('0b'), hash: sha256, length: -1 }),
    /HKDF length must be a non-negative integer\./,
  );
  assert.throws(
    () => deriveHkdf({ input: hex('0b'), hash: sha256, length: 1.5 }),
    /HKDF length must be a non-negative integer\./,
  );
  assert.throws(
    () => deriveHkdf({ input: hex('0b'), hash: sha256, length: 255 * 32 + 1 }),
    /HKDF length must be <= 8160\./,
  );

  assert.throws(
    () => expandHkdf(/** @type {any} */ ({ hash: sha256, length: 16 })),
    /HKDF-Expand requires input\./,
  );
  assert.throws(
    () => expandHkdf({ input: hex('0b'), hash: sha256, length: -1 }),
    /HKDF-Expand length must be a non-negative integer\./,
  );
  assert.throws(
    () => expandHkdf({ input: new Uint8Array([1]), hash: sha256, length: 16 }),
    /HKDF-Expand input must be at least 32 bytes\./,
  );
  assert.throws(
    () => expandHkdf({
      input: hex('077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5'),
      hash: sha256,
      length: 255 * 32 + 1,
    }),
    /HKDF-Expand length must be <= 8160\./,
  );
  assert.throws(
    () => expandHkdf({
      input: hex('077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5'),
      info: /** @type {any} */ (1),
      hash: sha256,
      length: 16,
    }),
    /HKDF info must be a Uint8Array or string\./,
  );

  assert.throws(
    () => extractHkdf(/** @type {any} */ ({ hash: sha256 })),
    /HKDF requires input\./,
  );
  assert.throws(
    () => extractHkdf(/** @type {any} */ ({ input: hex('0b'), hash: null })),
    /HKDF requires hash\./,
  );

  assert.throws(
    () => registry.derive({
      name: 'HKDF',
      input: hex('0b'),
      length: 16,
    }),
    /HKDF requires hash\./,
  );
  assert.throws(
    () => registry.derive({
      name: 'HKDF',
      input: hex('0b'),
      hash: '',
      length: 16,
    }),
    /HKDF requires hash\./,
  );
  assert.throws(
    () => registry.derive({
      name: 'HKDF',
      input: hex('0b'),
      hash: 'SHA512',
      length: 16,
    }),
    /Hash not registered: SHA512\./,
  );
  assert.throws(
    () => registry.derive({
      name: 'HKDF-Extract',
      input: hex('0b'),
    }),
    /HKDF-Extract requires hash\./,
  );
  assert.throws(
    () => registry.derive({
      name: 'HKDF-Extract',
      input: hex('0b'),
      hash: 'SHA512',
    }),
    /Hash not registered: SHA512\./,
  );
  assert.throws(
    () => registry.derive({
      name: 'HKDF-Expand',
      input: hex('0b'),
      length: 16,
    }),
    /HKDF-Expand requires hash\./,
  );
  assert.throws(
    () => registry.derive({
      name: 'HKDF-Expand',
      input: hex('0b'),
      hash: 'SHA512',
      length: 16,
    }),
    /Hash not registered: SHA512\./,
  );
  assert.throws(
    () => registry.derive({
      name: 'HKDF-Expand',
      input: hex('0b'),
      hash: 'SHA256',
      length: -1,
    }),
    /HKDF-Expand length must be a non-negative integer\./,
  );
  assert.throws(
    () => registry.derive({
      name: 'HKDF-Expand',
      input: new Uint8Array([1]),
      hash: 'SHA256',
      length: 16,
    }),
    /HKDF-Expand input must be at least 32 bytes\./,
  );
});

test('createDerivedKeyCipher AES-CBC derives key+IV with HKDF', () => {
  const registry = createClassicRegistry()
    .use(classicHashesPreset)
    .use(hkdfPreset);
  const salt = hex('0102030405060708');
  const cipher = registry.createDerivedKeyCipher({
    cipher: 'AES',
    mode: 'CBC',
    padding: 'Pkcs7',
    kdf: {
      name: 'HKDF',
      input: hex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'),
      info: new TextEncoder().encode('cbc:v1'),
      hash: 'SHA256',
    },
    keySize: 32,
  });

  const plaintext = new TextEncoder().encode('hello-hkdf-cbc');
  const ciphertext = cipher.encrypt(plaintext, { salt });
  assert.deepEqual(cipher.decrypt(ciphertext, { salt }), plaintext);
});

test('createDerivedKeyCipher AES-GCM derives key only and requires operation nonce', () => {
  const registry = createClassicRegistry()
    .use(classicHashesPreset)
    .use(hkdfPreset);
  const salt = hex('0102030405060708');
  const nonce = hex('000000000000000000000000');
  const cipher = registry.createDerivedKeyCipher({
    cipher: 'AES',
    mode: 'GCM',
    kdf: {
      name: 'HKDF',
      input: hex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'),
      salt,
      info: new TextEncoder().encode('gcm:v1'),
      hash: 'SHA256',
    },
    keySize: 32,
  });

  const plaintext = new TextEncoder().encode('hello-hkdf-gcm');
  assert.throws(() => cipher.encrypt(plaintext), /requires/);
  const sealed = cipher.encrypt(plaintext, { nonce, tagLength: 16 });
  assert.deepEqual(cipher.decrypt(sealed, { nonce }), plaintext);
});

test('CommonJS build can be required', () => {
  const packageExports = require('../packages/kdfs/dist/hkdf.cjs');
  assert.equal(typeof packageExports.deriveHkdf, 'function');
  assert.equal(typeof packageExports.extractHkdf, 'function');
  assert.equal(typeof packageExports.expandHkdf, 'function');
  assert.equal(packageExports.hkdf.name, 'HKDF');
  assert.equal(packageExports.hkdfExtract.name, 'HKDF-Extract');
  assert.equal(packageExports.hkdfExpand.name, 'HKDF-Expand');
  assert.equal(packageExports.hkdfPreset.name, 'hkdf');
});

test('generated declarations export the public API', async () => {
  const dts = await readFile(new URL('../packages/kdfs/dist/hkdf.d.ts', import.meta.url), 'utf8');
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
