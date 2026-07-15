import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { test } from 'node:test';
import vm from 'node:vm';
import * as esbuild from 'esbuild';

const require = createRequire(import.meta.url);

test('CommonJS builds can be required', () => {
  const core = require('../packages/core/dist/index.cjs');
  const classic = require('../packages/classic/dist/index.cjs');
  const hashes = require('../packages/classic/dist/hashes.cjs');

  assert.equal(typeof core.createRegistry, 'function');
  assert.equal(typeof classic.registry.createCipher, 'function');
  assert.equal(typeof hashes.registerClassicHashes, 'function');
});

test('browser IIFE builds expose globals', async () => {
  const context = {};
  vm.createContext(context);

  for (const file of [
    '../packages/core/dist/jscrypto-core.iife.js',
    '../packages/core/dist/jscrypto-core.iife.min.js',
    '../packages/classic/dist/jscrypto-classic.iife.js',
    '../packages/classic/dist/jscrypto-classic.iife.min.js',
    '../packages/classic/dist/jscrypto-classic-hashes.iife.min.js',
  ]) {
    const code = await readFile(new URL(file, import.meta.url), 'utf8');
    vm.runInContext(code, context);
  }

  assert.equal(typeof context.jscryptoCore.createRegistry, 'function');
  assert.equal(typeof context.jscryptoClassic.registry.createCipher, 'function');
  assert.equal(typeof context.jscryptoClassicHashes.registerClassicHashes, 'function');
  context.jscryptoClassicHashes.registerClassicHashes(context.jscryptoClassic.registry);
  assert.equal(context.jscryptoClassic.registry.getHash('SHA256').name, 'SHA256');
});

test('main classic IIFE entry graph excludes hashes implementations', async () => {
  const result = await esbuild.build({
    entryPoints: ['packages/classic/src/index.ts'],
    bundle: true,
    write: false,
    metafile: true,
    format: 'iife',
    globalName: 'jscryptoClassic',
    target: 'es2015',
    external: ['@jscrypto/core'],
  });
  const inputs = Object.keys(result.metafile.inputs);
  assert.equal(inputs.some((path) => /packages\/classic\/src\/hashes\//.test(path)), false);
});

test('UMD builds support AMD loaders', async () => {
  const context = {
    modules: [],
    define(_deps, factory) {
      context.modules.push(factory());
    },
  };
  context.define.amd = true;
  vm.createContext(context);

  for (const file of [
    '../packages/core/dist/jscrypto-core.umd.js',
    '../packages/core/dist/jscrypto-core.umd.min.js',
    '../packages/classic/dist/jscrypto-classic.umd.js',
    '../packages/classic/dist/jscrypto-classic.umd.min.js',
  ]) {
    const code = await readFile(new URL(file, import.meta.url), 'utf8');
    vm.runInContext(code, context);
  }

  assert.equal(typeof context.modules[0].createRegistry, 'function');
  assert.equal(typeof context.modules[2].registry.createCipher, 'function');
});
