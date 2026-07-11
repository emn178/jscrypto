import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { test } from 'node:test';
import vm from 'node:vm';

const require = createRequire(import.meta.url);

test('CommonJS builds can be required', () => {
  const core = require('../packages/core/dist/index.cjs');
  const classic = require('../packages/classic/dist/index.cjs');

  assert.equal(typeof core.createRegistry, 'function');
  assert.equal(typeof classic.registry.createCipher, 'function');
});

test('browser IIFE builds expose globals', async () => {
  const context = {};
  vm.createContext(context);

  for (const file of [
    '../packages/core/dist/crypto-core.iife.js',
    '../packages/core/dist/crypto-core.iife.min.js',
    '../packages/classic/dist/crypto-classic.iife.js',
    '../packages/classic/dist/crypto-classic.iife.min.js',
  ]) {
    const code = await readFile(new URL(file, import.meta.url), 'utf8');
    vm.runInContext(code, context);
  }

  assert.equal(typeof context.cryptoCore.createRegistry, 'function');
  assert.equal(typeof context.cryptoClassic.registry.createCipher, 'function');
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
    '../packages/core/dist/crypto-core.umd.js',
    '../packages/core/dist/crypto-core.umd.min.js',
    '../packages/classic/dist/crypto-classic.umd.js',
    '../packages/classic/dist/crypto-classic.umd.min.js',
  ]) {
    const code = await readFile(new URL(file, import.meta.url), 'utf8');
    vm.runInContext(code, context);
  }

  assert.equal(typeof context.modules[0].createRegistry, 'function');
  assert.equal(typeof context.modules[2].registry.createCipher, 'function');
});
