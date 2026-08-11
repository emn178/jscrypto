import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { test } from 'node:test';
import vm from 'node:vm';
import commonjs from '@rollup/plugin-commonjs';
import { nodeResolve } from '@rollup/plugin-node-resolve';
import { rollup } from 'rollup';
import ts from 'typescript';

const require = createRequire(import.meta.url);

test('CommonJS builds can be required', () => {
  const core = require('../../packages/core/dist/index.cjs');
  const ciphers = require('../../packages/ciphers/dist/index.cjs');
  const aes = require('../../packages/ciphers/dist/aes.cjs');
  const chacha20 = require('../../packages/ciphers/dist/chacha20.cjs');
  const speck = require('../../packages/ciphers/dist/speck.cjs');
  const modes = require('../../packages/modes/dist/index.cjs');
  const paddings = require('../../packages/paddings/dist/index.cjs');
  const pkcs5 = require('../../packages/paddings/dist/pkcs5.cjs');
  const kdfs = require('../../packages/kdfs/dist/index.cjs');
  const hkdf = require('../../packages/kdfs/dist/hkdf.cjs');
  const scrypt = require('../../packages/kdfs/dist/scrypt.cjs');
  const argon2 = require('../../packages/kdfs/dist/argon2.cjs');
  const formats = require('../../packages/formats/dist/index.cjs');
  const componentHashes = require('../../packages/hashes/dist/index.cjs');
  const suite = require('../../packages/suite/dist/index.cjs');
  const suiteBasic = require('../../packages/suite/dist/basic.cjs');
  const suiteAll = require('../../packages/suite/dist/all.cjs');

  assert.equal(typeof core.createRegistry, 'function');
  assert.equal(ciphers.ciphersPreset().kind, 'preset');
  assert.equal(ciphers.classicCiphersPreset().kind, 'preset');
  assert.equal(typeof aes.createAesCipher, 'function');
  assert.equal(aes.aesPreset.components()[0].name, 'AES');
  assert.deepEqual(
    aes.aesPreset.components().map((component) => component.name),
    ['AES', 'AES-GCM', 'AES-CCM'],
  );
  assert.equal(aes.aesGcm.kind, 'aead');
  assert.equal(aes.aesCcm.kind, 'aead');
  assert.equal(aes.aesCcm.name, 'AES-CCM');
  assert.equal(typeof chacha20.chacha20.createEncryptor, 'function');
  assert.equal(chacha20.chacha20.name, 'ChaCha20');
  assert.equal(chacha20.xchacha20.name, 'XChaCha20');
  assert.equal(chacha20.chacha20Poly1305.name, 'ChaCha20-Poly1305');
  assert.equal(chacha20.chacha20Poly1305.kind, 'aead');
  assert.equal(typeof chacha20.chacha20Poly1305.create, 'function');
  assert.equal(chacha20.xchacha20Poly1305.name, 'XChaCha20-Poly1305');
  assert.equal(chacha20.chacha20Preset.name, 'chacha20');
  assert.equal(typeof speck.createSpeckCipher, 'function');
  assert.equal(speck.createRegistry, undefined);
  assert.equal(speck.speck64_128.name, 'SPECK64/128');
  assert.equal(speck.speckPreset.name, 'speck');
  assert.equal(modes.modesPreset().kind, 'preset');
  assert.equal(paddings.paddingsPreset().kind, 'preset');
  assert.equal(pkcs5.pkcs5Preset.name, 'pkcs5');
  assert.equal(kdfs.kdfsPreset().kind, 'preset');
  assert.equal(kdfs.classicKdfsPreset().kind, 'preset');
  assert.equal(typeof hkdf.deriveHkdf, 'function');
  assert.equal(typeof hkdf.extractHkdf, 'function');
  assert.equal(typeof hkdf.expandHkdf, 'function');
  assert.equal(hkdf.hkdf.name, 'HKDF');
  assert.equal(hkdf.hkdfExtract.name, 'HKDF-Extract');
  assert.equal(hkdf.hkdfExpand.name, 'HKDF-Expand');
  assert.equal(hkdf.hkdfPreset.name, 'hkdf');
  assert.equal(typeof scrypt.deriveScrypt, 'function');
  assert.equal(scrypt.scrypt.name, 'Scrypt');
  assert.equal(scrypt.scryptPreset.name, 'scrypt');
  assert.equal(typeof argon2.deriveArgon2, 'function');
  assert.equal(argon2.argon2.name, 'Argon2');
  assert.equal(argon2.argon2Preset.name, 'argon2');
  assert.equal(formats.formatsPreset().kind, 'preset');
  assert.equal(componentHashes.hashesPreset.kind, 'preset');
  assert.equal(typeof suite.registry.createCipher, 'function');
  assert.equal(suite.registry.getHash('SHA256').name, 'SHA256');
  assert.equal(suite.basicPreset().kind, 'preset');
  assert.equal(suite.allPreset().kind, 'preset');
  assert.equal(suite.suitePreset().name, 'basic');
  assert.equal(suiteBasic.registry.get('cipher', 'AES').name, 'AES');
  assert.throws(() => suiteBasic.registry.get('cipher', 'RC4'), /Component not found: cipher:RC4/);
  assert.equal(suiteBasic.registry.get('kdf', 'HKDF').name, 'HKDF');
  assert.equal(suiteAll.allRegistry.get('cipher', 'RC4').name, 'RC4');
  assert.equal(suiteAll.allRegistry.get('cipher', 'SPECK64/128').name, 'SPECK64/128');
  assert.equal(suiteAll.allRegistry.get('cipher', 'ChaCha20').name, 'ChaCha20');
});

test('package exports route Node imports to package builds', async () => {
  if (typeof import.meta.resolve === 'function') {
    assert.match(import.meta.resolve('@jscrypto/ciphers'), /packages[\\/]ciphers[\\/]dist[\\/]index\.node\.mjs$/);
    assert.match(import.meta.resolve('@jscrypto/ciphers/aes'), /packages[\\/]ciphers[\\/]dist[\\/]aes\.node\.mjs$/);
    assert.match(import.meta.resolve('@jscrypto/ciphers/aes/browser'), /packages[\\/]ciphers[\\/]dist[\\/]jscrypto-ciphers-aes\.iife\.min\.js$/);
    assert.match(import.meta.resolve('@jscrypto/ciphers/chacha20'), /packages[\\/]ciphers[\\/]dist[\\/]chacha20\.mjs$/);
    assert.match(import.meta.resolve('@jscrypto/ciphers/chacha20/browser'), /packages[\\/]ciphers[\\/]dist[\\/]jscrypto-ciphers-chacha20\.iife\.min\.js$/);
    assert.match(import.meta.resolve('@jscrypto/ciphers/speck'), /packages[\\/]ciphers[\\/]dist[\\/]speck\.mjs$/);
    assert.match(import.meta.resolve('@jscrypto/ciphers/speck/browser'), /packages[\\/]ciphers[\\/]dist[\\/]jscrypto-ciphers-speck\.iife\.min\.js$/);
    assert.match(import.meta.resolve('@jscrypto/modes/cbc/browser'), /packages[\\/]modes[\\/]dist[\\/]jscrypto-modes-cbc\.iife\.min\.js$/);
    assert.match(import.meta.resolve('@jscrypto/paddings/pkcs7/browser'), /packages[\\/]paddings[\\/]dist[\\/]jscrypto-paddings-pkcs7\.iife\.min\.js$/);
    assert.match(import.meta.resolve('@jscrypto/paddings/pkcs5/browser'), /packages[\\/]paddings[\\/]dist[\\/]jscrypto-paddings-pkcs5\.iife\.min\.js$/);
    assert.match(import.meta.resolve('@jscrypto/kdfs/hkdf'), /packages[\\/]kdfs[\\/]dist[\\/]hkdf\.mjs$/);
    assert.match(import.meta.resolve('@jscrypto/kdfs/hkdf/browser'), /packages[\\/]kdfs[\\/]dist[\\/]jscrypto-kdfs-hkdf\.iife\.min\.js$/);
    assert.match(import.meta.resolve('@jscrypto/kdfs/scrypt'), /packages[\\/]kdfs[\\/]dist[\\/]scrypt\.mjs$/);
    assert.match(import.meta.resolve('@jscrypto/kdfs/scrypt/browser'), /packages[\\/]kdfs[\\/]dist[\\/]jscrypto-kdfs-scrypt\.iife\.min\.js$/);
    assert.match(import.meta.resolve('@jscrypto/kdfs/argon2'), /packages[\\/]kdfs[\\/]dist[\\/]argon2\.mjs$/);
    assert.match(import.meta.resolve('@jscrypto/kdfs/argon2/browser'), /packages[\\/]kdfs[\\/]dist[\\/]jscrypto-kdfs-argon2\.iife\.min\.js$/);
    assert.match(import.meta.resolve('@jscrypto/hashes/sha256/browser'), /packages[\\/]hashes[\\/]dist[\\/]jscrypto-hashes-sha256\.iife\.min\.js$/);
    assert.match(import.meta.resolve('@jscrypto/suite'), /packages[\\/]suite[\\/]dist[\\/]index\.node\.mjs$/);
    assert.match(import.meta.resolve('@jscrypto/suite/basic'), /packages[\\/]suite[\\/]dist[\\/]basic\.mjs$/);
    assert.match(import.meta.resolve('@jscrypto/suite/all'), /packages[\\/]suite[\\/]dist[\\/]all\.mjs$/);
  } else {
    assert.match(require.resolve('@jscrypto/ciphers'), /packages[\\/]ciphers[\\/]dist[\\/]index\.node\.cjs$/);
    assert.match(require.resolve('@jscrypto/ciphers/aes'), /packages[\\/]ciphers[\\/]dist[\\/]aes\.node\.cjs$/);
    assert.match(require.resolve('@jscrypto/ciphers/aes/browser'), /packages[\\/]ciphers[\\/]dist[\\/]jscrypto-ciphers-aes\.iife\.min\.js$/);
    assert.match(require.resolve('@jscrypto/ciphers/chacha20'), /packages[\\/]ciphers[\\/]dist[\\/]chacha20\.cjs$/);
    assert.match(require.resolve('@jscrypto/ciphers/chacha20/browser'), /packages[\\/]ciphers[\\/]dist[\\/]jscrypto-ciphers-chacha20\.iife\.min\.js$/);
    assert.match(require.resolve('@jscrypto/ciphers/speck'), /packages[\\/]ciphers[\\/]dist[\\/]speck\.cjs$/);
    assert.match(require.resolve('@jscrypto/ciphers/speck/browser'), /packages[\\/]ciphers[\\/]dist[\\/]jscrypto-ciphers-speck\.iife\.min\.js$/);
    assert.match(require.resolve('@jscrypto/modes/cbc/browser'), /packages[\\/]modes[\\/]dist[\\/]jscrypto-modes-cbc\.iife\.min\.js$/);
    assert.match(require.resolve('@jscrypto/paddings/pkcs7/browser'), /packages[\\/]paddings[\\/]dist[\\/]jscrypto-paddings-pkcs7\.iife\.min\.js$/);
    assert.match(require.resolve('@jscrypto/paddings/pkcs5/browser'), /packages[\\/]paddings[\\/]dist[\\/]jscrypto-paddings-pkcs5\.iife\.min\.js$/);
    assert.match(require.resolve('@jscrypto/kdfs/hkdf'), /packages[\\/]kdfs[\\/]dist[\\/]hkdf\.cjs$/);
    assert.match(require.resolve('@jscrypto/kdfs/hkdf/browser'), /packages[\\/]kdfs[\\/]dist[\\/]jscrypto-kdfs-hkdf\.iife\.min\.js$/);
    assert.match(require.resolve('@jscrypto/kdfs/scrypt'), /packages[\\/]kdfs[\\/]dist[\\/]scrypt\.cjs$/);
    assert.match(require.resolve('@jscrypto/kdfs/scrypt/browser'), /packages[\\/]kdfs[\\/]dist[\\/]jscrypto-kdfs-scrypt\.iife\.min\.js$/);
    assert.match(require.resolve('@jscrypto/kdfs/argon2'), /packages[\\/]kdfs[\\/]dist[\\/]argon2\.cjs$/);
    assert.match(require.resolve('@jscrypto/kdfs/argon2/browser'), /packages[\\/]kdfs[\\/]dist[\\/]jscrypto-kdfs-argon2\.iife\.min\.js$/);
    assert.match(require.resolve('@jscrypto/hashes/sha256/browser'), /packages[\\/]hashes[\\/]dist[\\/]jscrypto-hashes-sha256\.iife\.min\.js$/);
    assert.match(require.resolve('@jscrypto/suite'), /packages[\\/]suite[\\/]dist[\\/]index\.node\.cjs$/);
    assert.match(require.resolve('@jscrypto/suite/basic'), /packages[\\/]suite[\\/]dist[\\/]basic\.cjs$/);
    assert.match(require.resolve('@jscrypto/suite/all'), /packages[\\/]suite[\\/]dist[\\/]all\.cjs$/);
  }

  const ciphers = await import('@jscrypto/ciphers');
  const aes = await import('@jscrypto/ciphers/aes');
  const chacha20 = await import('@jscrypto/ciphers/chacha20');
  const speck = await import('@jscrypto/ciphers/speck');
  const pkcs5 = await import('@jscrypto/paddings/pkcs5');
  const hkdf = await import('@jscrypto/kdfs/hkdf');
  const scrypt = await import('@jscrypto/kdfs/scrypt');
  const argon2 = await import('@jscrypto/kdfs/argon2');
  const suite = await import('@jscrypto/suite');
  const suiteBasic = await import('@jscrypto/suite/basic');
  const suiteAll = await import('@jscrypto/suite/all');

  assert.equal(ciphers.ciphersPreset().kind, 'preset');
  assert.equal(typeof aes.createAesCipher, 'function');
  assert.equal(aes.aesPreset.components()[0].name, 'AES');
  assert.deepEqual(
    aes.aesPreset.components().map((component) => component.name),
    ['AES', 'AES-GCM', 'AES-CCM'],
  );
  assert.equal(chacha20.chacha20Preset.name, 'chacha20');
  assert.equal(speck.speckPreset.name, 'speck');
  assert.equal(pkcs5.pkcs5Preset.name, 'pkcs5');
  assert.equal(hkdf.hkdfPreset.name, 'hkdf');
  assert.equal(scrypt.scryptPreset.name, 'scrypt');
  assert.equal(argon2.argon2Preset.name, 'argon2');
  assert.equal(typeof suite.registry.createCipher, 'function');
  assert.equal(suite.registry.getHash('SHA256').name, 'SHA256');
  assert.equal(suiteBasic.registry.get('cipher', 'AES').name, 'AES');
  assert.throws(() => suiteBasic.registry.get('cipher', 'RC4'), /Component not found: cipher:RC4/);
  assert.equal(suiteAll.allRegistry.get('cipher', 'RC4').name, 'RC4');
});

test('browser IIFE builds expose globals', async () => {
  const context = {};
  vm.createContext(context);

  for (const file of [
    '../../packages/core/dist/jscrypto-core.iife.js',
    '../../packages/core/dist/jscrypto-core.iife.min.js',
    '../../packages/ciphers/dist/jscrypto-ciphers.iife.min.js',
    '../../packages/modes/dist/jscrypto-modes.iife.min.js',
    '../../packages/paddings/dist/jscrypto-paddings.iife.min.js',
    '../../packages/kdfs/dist/jscrypto-kdfs.iife.min.js',
    '../../packages/formats/dist/jscrypto-formats.iife.min.js',
    '../../packages/hashes/dist/jscrypto-hashes.iife.min.js',
    '../../packages/suite/dist/jscrypto-suite.iife.min.js',
    '../../packages/suite/dist/jscrypto-suite-basic.iife.min.js',
    '../../packages/suite/dist/jscrypto-suite-all.iife.min.js',
    '../../packages/ciphers/dist/jscrypto-ciphers-aes.iife.min.js',
    '../../packages/ciphers/dist/jscrypto-ciphers-chacha20.iife.min.js',
    '../../packages/ciphers/dist/jscrypto-ciphers-speck.iife.min.js',
    '../../packages/modes/dist/jscrypto-modes-cbc.iife.min.js',
    '../../packages/paddings/dist/jscrypto-paddings-pkcs5.iife.min.js',
    '../../packages/paddings/dist/jscrypto-paddings-pkcs7.iife.min.js',
    '../../packages/kdfs/dist/jscrypto-kdfs-hkdf.iife.min.js',
    '../../packages/kdfs/dist/jscrypto-kdfs-scrypt.iife.min.js',
    '../../packages/kdfs/dist/jscrypto-kdfs-argon2.iife.min.js',
    '../../packages/hashes/dist/jscrypto-hashes-sha256.iife.min.js',
  ]) {
    const code = await readFile(new URL(file, import.meta.url), 'utf8');
    vm.runInContext(code, context);
  }

  assert.equal(typeof context.jscryptoCore.createRegistry, 'function');
  assert.equal(context.jscryptoCiphers.ciphersPreset().kind, 'preset');
  assert.equal(context.jscryptoCiphers.chacha20Preset.name, 'chacha20');
  assert.equal(context.jscryptoCiphers.speckPreset.name, 'speck');
  assert.equal(context.jscryptoModes.modesPreset().kind, 'preset');
  assert.equal(context.jscryptoPaddings.paddingsPreset().kind, 'preset');
  assert.equal(context.jscryptoKdfs.kdfsPreset().kind, 'preset');
  assert.equal(context.jscryptoKdfs.hkdfPreset.name, 'hkdf');
  assert.equal(context.jscryptoFormats.formatsPreset().kind, 'preset');
  assert.equal(context.jscryptoHashes.hashesPreset.kind, 'preset');
  assert.equal(typeof context.jscryptoSuite.registry.createCipher, 'function');
  assert.equal(context.jscryptoSuite.registry.getHash('SHA256').name, 'SHA256');
  assert.equal(context.jscryptoSuiteBasic.registry.get('cipher', 'AES').name, 'AES');
  assert.throws(() => context.jscryptoSuiteBasic.registry.get('cipher', 'RC4'), /Component not found: cipher:RC4/);
  assert.equal(context.jscryptoSuiteBasic.registry.get('kdf', 'HKDF').name, 'HKDF');
  assert.equal(context.jscryptoSuiteAll.allRegistry.get('cipher', 'RC4').name, 'RC4');
  assert.equal(context.jscryptoSuiteAll.allRegistry.get('cipher', 'SPECK64/128').name, 'SPECK64/128');
  assert.equal(context.jscryptoSuiteAll.allRegistry.get('cipher', 'ChaCha20').name, 'ChaCha20');
  assert.equal(context.jscryptoCiphersAes.aesPreset.name, 'aes');
  assert.equal(context.jscryptoCiphersAes.aesPreset.components()[0].name, 'AES');
  // Spread in the host realm first: `.map` on a vm-context array would
  // otherwise produce a cross-realm array that fails deepStrictEqual.
  assert.deepEqual(
    [...context.jscryptoCiphersAes.aesPreset.components()].map((component) => component.name),
    ['AES', 'AES-GCM', 'AES-CCM'],
  );
  assert.equal(context.jscryptoCiphersChacha20.chacha20Preset.name, 'chacha20');
  assert.equal(context.jscryptoCiphersSpeck.speckPreset.name, 'speck');
  assert.equal(context.jscryptoModesCbc.cbcPreset.name, 'cbc');
  assert.equal(context.jscryptoPaddingsPkcs5.pkcs5Preset.name, 'pkcs5');
  assert.equal(context.jscryptoPaddingsPkcs7.pkcs7Preset.name, 'pkcs7');
  assert.equal(context.jscryptoKdfsHkdf.hkdfPreset.name, 'hkdf');
  assert.equal(context.jscryptoHashesSha256.sha256Preset.name, 'sha256');
});

test('basic suite IIFE entry graph excludes optional component implementations', async () => {
  const bundle = await rollup({
    input: 'packages/suite/src/basic.ts',
    external: ['@jscrypto/core'],
    plugins: [
      {
        name: 'resolve-typescript-extensions',
        async resolveId(source, importer, options) {
          if (!importer || !source.startsWith('.') || !source.endsWith('.js')) {
            return null;
          }

          return this.resolve(`${source.slice(0, -3)}.ts`, importer, {
            ...options,
            skipSelf: true,
          });
        },
      },
      {
        name: 'transpile-typescript',
        transform(code, id) {
          if (!id.endsWith('.ts')) {
            return null;
          }

          const result = ts.transpileModule(code, {
            fileName: id,
            compilerOptions: {
              target: ts.ScriptTarget.ES2020,
              module: ts.ModuleKind.ESNext,
            },
          });

          return {
            code: result.outputText,
            map: { mappings: '' },
          };
        },
      },
      nodeResolve(),
      commonjs(),
    ],
  });

  try {
    assert.equal(
      bundle.watchFiles.some((path) => /packages[\\/]ciphers[\\/]src[\\/]des\.ts$/.test(path)),
      false,
    );
    assert.equal(
      bundle.watchFiles.some((path) => /packages[\\/]ciphers[\\/]src[\\/]rc4\.ts$/.test(path)),
      false,
    );
    assert.equal(
      bundle.watchFiles.some((path) => /packages[\\/]ciphers[\\/]src[\\/]speck\.ts$/.test(path)),
      false,
    );
    assert.equal(
      bundle.watchFiles.some((path) => /packages[\\/]ciphers[\\/]src[\\/]chacha20\.ts$/.test(path)),
      false,
    );
    assert.equal(
      bundle.watchFiles.some((path) => /packages[\\/]kdfs[\\/]src[\\/]scrypt\.ts$/.test(path)),
      false,
    );
    assert.equal(
      bundle.watchFiles.some((path) => /packages[\\/]kdfs[\\/]src[\\/]argon2\.ts$/.test(path)),
      false,
    );
  } finally {
    await bundle.close();
  }
});

test('UMD builds support AMD loaders', async () => {
  const modules = new Map();
  const context = {
    define(deps, factory) {
      context.lastDeps = [...deps];
      const exports = {};
      const args = deps.map((dep) => {
        if (dep === 'exports') {
          return exports;
        }
        assert.ok(modules.has(dep), `missing AMD dependency: ${dep}`);
        return modules.get(dep);
      });
      const returned = factory(...args);
      context.lastExports = returned || exports;
    },
  };
  context.define.amd = true;
  vm.createContext(context);

  function loadAmd(moduleId, code) {
    context.lastExports = undefined;
    vm.runInContext(code, context);
    assert.ok(context.lastExports, `${moduleId} did not export an AMD module`);
    modules.set(moduleId, context.lastExports);
    return {
      deps: context.lastDeps,
      exports: context.lastExports,
    };
  }

  for (const file of [
    '../../packages/core/dist/jscrypto-core.umd.js',
    '../../packages/core/dist/jscrypto-core.umd.min.js',
  ]) {
    const code = await readFile(new URL(file, import.meta.url), 'utf8');
    const loaded = loadAmd('@jscrypto/core', code);
    assert.deepEqual(loaded.deps, ['exports']);
  }

  assert.equal(typeof modules.get('@jscrypto/core').createRegistry, 'function');

  for (const file of [
    '../../packages/suite/dist/jscrypto-suite.umd.js',
    '../../packages/suite/dist/jscrypto-suite.umd.min.js',
  ]) {
    const code = await readFile(new URL(file, import.meta.url), 'utf8');
    const loaded = loadAmd('@jscrypto/suite', code);
    const suite = loaded.exports;
    assert.deepEqual(loaded.deps, ['exports', '@jscrypto/core']);
    assert.equal(typeof suite.createBasicRegistry, 'function');
    assert.equal(typeof suite.registry.createCipher, 'function');
  }
});
