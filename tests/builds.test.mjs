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
  const core = require('../packages/core/dist/index.cjs');
  const ciphers = require('../packages/ciphers/dist/index.cjs');
  const aes = require('../packages/ciphers/dist/aes.cjs');
  const chacha20 = require('../packages/ciphers/dist/chacha20.cjs');
  const speck = require('../packages/ciphers/dist/speck.cjs');
  const modes = require('../packages/modes/dist/index.cjs');
  const paddings = require('../packages/paddings/dist/index.cjs');
  const kdfs = require('../packages/kdfs/dist/index.cjs');
  const hkdf = require('../packages/kdfs/dist/hkdf.cjs');
  const formats = require('../packages/formats/dist/index.cjs');
  const componentHashes = require('../packages/hashes/dist/index.cjs');
  const suite = require('../packages/suite/dist/index.cjs');
  const suiteBasic = require('../packages/suite/dist/basic.cjs');
  const suiteAll = require('../packages/suite/dist/all.cjs');
  const classic = require('../packages/classic/dist/index.cjs');
  const hashes = require('../packages/classic/dist/hashes.cjs');

  assert.equal(typeof core.createRegistry, 'function');
  assert.equal(ciphers.ciphersPreset().kind, 'preset');
  assert.equal(ciphers.classicCiphersPreset().kind, 'preset');
  assert.equal(typeof aes.createAesCipher, 'function');
  assert.equal(aes.aesPreset.components()[0].name, 'AES');
  assert.equal(chacha20.chacha20Preset.name, 'chacha20');
  assert.equal(speck.speckPreset.name, 'speck');
  assert.equal(modes.modesPreset().kind, 'preset');
  assert.equal(paddings.paddingsPreset().kind, 'preset');
  assert.equal(kdfs.kdfsPreset().kind, 'preset');
  assert.equal(kdfs.classicKdfsPreset().kind, 'preset');
  assert.equal(hkdf.hkdfPreset.name, 'hkdf');
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
  assert.equal(typeof classic.registry.createCipher, 'function');
  assert.equal(typeof classic.speckPreset, 'undefined');
  assert.equal(typeof classic.chacha20Preset, 'undefined');
  assert.equal(typeof classic.hkdfPreset, 'undefined');
  assert.equal(hashes.classicHashesPreset.kind, 'preset');
  assert.equal(typeof hashes.registerClassicHashes, 'undefined');
});

test('package exports route Node imports to the native classic build', async () => {
  if (typeof import.meta.resolve === 'function') {
    assert.match(import.meta.resolve('@jscrypto/classic'), /packages[\\/]classic[\\/]dist[\\/]index\.node\.mjs$/);
    assert.match(import.meta.resolve('@jscrypto/ciphers'), /packages[\\/]ciphers[\\/]dist[\\/]index\.node\.mjs$/);
    assert.match(import.meta.resolve('@jscrypto/ciphers/aes'), /packages[\\/]ciphers[\\/]dist[\\/]aes\.node\.mjs$/);
    assert.match(import.meta.resolve('@jscrypto/ciphers/aes/browser'), /packages[\\/]ciphers[\\/]dist[\\/]jscrypto-ciphers-aes\.iife\.min\.js$/);
    assert.match(import.meta.resolve('@jscrypto/ciphers/chacha20'), /packages[\\/]ciphers[\\/]dist[\\/]chacha20\.mjs$/);
    assert.match(import.meta.resolve('@jscrypto/ciphers/chacha20/browser'), /packages[\\/]ciphers[\\/]dist[\\/]jscrypto-ciphers-chacha20\.iife\.min\.js$/);
    assert.match(import.meta.resolve('@jscrypto/ciphers/speck'), /packages[\\/]ciphers[\\/]dist[\\/]speck\.mjs$/);
    assert.match(import.meta.resolve('@jscrypto/ciphers/speck/browser'), /packages[\\/]ciphers[\\/]dist[\\/]jscrypto-ciphers-speck\.iife\.min\.js$/);
    assert.match(import.meta.resolve('@jscrypto/modes/cbc/browser'), /packages[\\/]modes[\\/]dist[\\/]jscrypto-modes-cbc\.iife\.min\.js$/);
    assert.match(import.meta.resolve('@jscrypto/paddings/pkcs7/browser'), /packages[\\/]paddings[\\/]dist[\\/]jscrypto-paddings-pkcs7\.iife\.min\.js$/);
    assert.match(import.meta.resolve('@jscrypto/kdfs/hkdf'), /packages[\\/]kdfs[\\/]dist[\\/]hkdf\.mjs$/);
    assert.match(import.meta.resolve('@jscrypto/kdfs/hkdf/browser'), /packages[\\/]kdfs[\\/]dist[\\/]jscrypto-kdfs-hkdf\.iife\.min\.js$/);
    assert.match(import.meta.resolve('@jscrypto/hashes/sha256/browser'), /packages[\\/]hashes[\\/]dist[\\/]jscrypto-hashes-sha256\.iife\.min\.js$/);
    assert.match(import.meta.resolve('@jscrypto/suite'), /packages[\\/]suite[\\/]dist[\\/]index\.node\.mjs$/);
    assert.match(import.meta.resolve('@jscrypto/suite/basic'), /packages[\\/]suite[\\/]dist[\\/]basic\.mjs$/);
    assert.match(import.meta.resolve('@jscrypto/suite/all'), /packages[\\/]suite[\\/]dist[\\/]all\.mjs$/);
  } else {
    assert.match(require.resolve('@jscrypto/classic'), /packages[\\/]classic[\\/]dist[\\/]index\.node\.cjs$/);
    assert.match(require.resolve('@jscrypto/ciphers'), /packages[\\/]ciphers[\\/]dist[\\/]index\.node\.cjs$/);
    assert.match(require.resolve('@jscrypto/ciphers/aes'), /packages[\\/]ciphers[\\/]dist[\\/]aes\.node\.cjs$/);
    assert.match(require.resolve('@jscrypto/ciphers/aes/browser'), /packages[\\/]ciphers[\\/]dist[\\/]jscrypto-ciphers-aes\.iife\.min\.js$/);
    assert.match(require.resolve('@jscrypto/ciphers/chacha20'), /packages[\\/]ciphers[\\/]dist[\\/]chacha20\.cjs$/);
    assert.match(require.resolve('@jscrypto/ciphers/chacha20/browser'), /packages[\\/]ciphers[\\/]dist[\\/]jscrypto-ciphers-chacha20\.iife\.min\.js$/);
    assert.match(require.resolve('@jscrypto/ciphers/speck'), /packages[\\/]ciphers[\\/]dist[\\/]speck\.cjs$/);
    assert.match(require.resolve('@jscrypto/ciphers/speck/browser'), /packages[\\/]ciphers[\\/]dist[\\/]jscrypto-ciphers-speck\.iife\.min\.js$/);
    assert.match(require.resolve('@jscrypto/modes/cbc/browser'), /packages[\\/]modes[\\/]dist[\\/]jscrypto-modes-cbc\.iife\.min\.js$/);
    assert.match(require.resolve('@jscrypto/paddings/pkcs7/browser'), /packages[\\/]paddings[\\/]dist[\\/]jscrypto-paddings-pkcs7\.iife\.min\.js$/);
    assert.match(require.resolve('@jscrypto/kdfs/hkdf'), /packages[\\/]kdfs[\\/]dist[\\/]hkdf\.cjs$/);
    assert.match(require.resolve('@jscrypto/kdfs/hkdf/browser'), /packages[\\/]kdfs[\\/]dist[\\/]jscrypto-kdfs-hkdf\.iife\.min\.js$/);
    assert.match(require.resolve('@jscrypto/hashes/sha256/browser'), /packages[\\/]hashes[\\/]dist[\\/]jscrypto-hashes-sha256\.iife\.min\.js$/);
    assert.match(require.resolve('@jscrypto/suite'), /packages[\\/]suite[\\/]dist[\\/]index\.node\.cjs$/);
    assert.match(require.resolve('@jscrypto/suite/basic'), /packages[\\/]suite[\\/]dist[\\/]basic\.cjs$/);
    assert.match(require.resolve('@jscrypto/suite/all'), /packages[\\/]suite[\\/]dist[\\/]all\.cjs$/);
  }

  const classic = await import('@jscrypto/classic');
  const ciphers = await import('@jscrypto/ciphers');
  const aes = await import('@jscrypto/ciphers/aes');
  const chacha20 = await import('@jscrypto/ciphers/chacha20');
  const speck = await import('@jscrypto/ciphers/speck');
  const hkdf = await import('@jscrypto/kdfs/hkdf');
  const suite = await import('@jscrypto/suite');
  const suiteBasic = await import('@jscrypto/suite/basic');
  const suiteAll = await import('@jscrypto/suite/all');

  assert.equal(typeof classic.createAesCipher, 'function');
  assert.equal(typeof classic.registry.createCipher, 'function');
  assert.equal(typeof classic.speckPreset, 'undefined');
  assert.equal(typeof classic.chacha20Preset, 'undefined');
  assert.equal(typeof classic.hkdfPreset, 'undefined');
  assert.equal(ciphers.ciphersPreset().kind, 'preset');
  assert.equal(typeof aes.createAesCipher, 'function');
  assert.equal(aes.aesPreset.components()[0].name, 'AES');
  assert.equal(chacha20.chacha20Preset.name, 'chacha20');
  assert.equal(speck.speckPreset.name, 'speck');
  assert.equal(hkdf.hkdfPreset.name, 'hkdf');
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
    '../packages/core/dist/jscrypto-core.iife.js',
    '../packages/core/dist/jscrypto-core.iife.min.js',
    '../packages/ciphers/dist/jscrypto-ciphers.iife.min.js',
    '../packages/modes/dist/jscrypto-modes.iife.min.js',
    '../packages/paddings/dist/jscrypto-paddings.iife.min.js',
    '../packages/kdfs/dist/jscrypto-kdfs.iife.min.js',
    '../packages/formats/dist/jscrypto-formats.iife.min.js',
    '../packages/hashes/dist/jscrypto-hashes.iife.min.js',
    '../packages/suite/dist/jscrypto-suite.iife.min.js',
    '../packages/suite/dist/jscrypto-suite-basic.iife.min.js',
    '../packages/suite/dist/jscrypto-suite-all.iife.min.js',
    '../packages/classic/dist/jscrypto-classic.iife.js',
    '../packages/classic/dist/jscrypto-classic.iife.min.js',
    '../packages/classic/dist/jscrypto-classic-hashes.iife.min.js',
    '../packages/ciphers/dist/jscrypto-ciphers-aes.iife.min.js',
    '../packages/ciphers/dist/jscrypto-ciphers-chacha20.iife.min.js',
    '../packages/ciphers/dist/jscrypto-ciphers-speck.iife.min.js',
    '../packages/modes/dist/jscrypto-modes-cbc.iife.min.js',
    '../packages/paddings/dist/jscrypto-paddings-pkcs7.iife.min.js',
    '../packages/kdfs/dist/jscrypto-kdfs-hkdf.iife.min.js',
    '../packages/hashes/dist/jscrypto-hashes-sha256.iife.min.js',
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
  assert.equal(typeof context.jscryptoClassic.createClassicRegistry, 'function');
  assert.equal(typeof context.jscryptoClassic.registry.createCipher, 'function');
  assert.equal(context.jscryptoClassicHashes.classicHashesPreset.kind, 'preset');
  assert.equal(typeof context.jscryptoClassicHashes.registerClassicHashes, 'undefined');
  context.jscryptoClassic.registry.use(context.jscryptoClassicHashes.classicHashesPreset);
  assert.equal(context.jscryptoClassic.registry.getHash('SHA256').name, 'SHA256');
  assert.equal(context.jscryptoCiphersAes.aesPreset.name, 'aes');
  assert.equal(context.jscryptoCiphersAes.aesPreset.components()[0].name, 'AES');
  assert.equal(context.jscryptoCiphersChacha20.chacha20Preset.name, 'chacha20');
  assert.equal(context.jscryptoCiphersSpeck.speckPreset.name, 'speck');
  assert.equal(context.jscryptoModesCbc.cbcPreset.name, 'cbc');
  assert.equal(context.jscryptoPaddingsPkcs7.pkcs7Preset.name, 'pkcs7');
  assert.equal(context.jscryptoKdfsHkdf.hkdfPreset.name, 'hkdf');
  assert.equal(context.jscryptoHashesSha256.sha256Preset.name, 'sha256');

  for (const file of [
    '../packages/classic/dist/jscrypto-classic.iife.js',
    '../packages/classic/dist/jscrypto-classic.iife.min.js',
  ]) {
    const code = await readFile(new URL(file, import.meta.url), 'utf8');
    assert.equal(code.includes('@jscrypto/core v'), false);
  }
});

test('main classic IIFE entry graph excludes hashes implementations', async () => {
  const bundle = await rollup({
    input: 'packages/classic/src/index.ts',
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
      bundle.watchFiles.some((path) => /packages[\\/]classic[\\/]src[\\/]hashes[\\/]/.test(path)),
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
    '../packages/core/dist/jscrypto-core.umd.js',
    '../packages/core/dist/jscrypto-core.umd.min.js',
  ]) {
    const code = await readFile(new URL(file, import.meta.url), 'utf8');
    const loaded = loadAmd('@jscrypto/core', code);
    assert.deepEqual(loaded.deps, ['exports']);
  }

  assert.equal(typeof modules.get('@jscrypto/core').createRegistry, 'function');

  for (const file of [
    '../packages/classic/dist/jscrypto-classic.umd.js',
    '../packages/classic/dist/jscrypto-classic.umd.min.js',
  ]) {
    const code = await readFile(new URL(file, import.meta.url), 'utf8');
    const loaded = loadAmd('@jscrypto/classic', code);
    const classic = loaded.exports;
    assert.deepEqual(loaded.deps, ['exports', '@jscrypto/core']);
    assert.equal(typeof classic.createClassicRegistry, 'function');
    assert.equal(typeof classic.registry.createCipher, 'function');
  }
});
