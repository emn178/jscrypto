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
  const classic = require('../packages/classic/dist/index.cjs');
  const hashes = require('../packages/classic/dist/hashes.cjs');

  assert.equal(typeof core.createRegistry, 'function');
  assert.equal(typeof classic.registry.createCipher, 'function');
  assert.equal(hashes.classicHashesPreset.kind, 'preset');
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
  assert.equal(typeof context.jscryptoClassic.createClassicRegistry, 'function');
  assert.equal(typeof context.jscryptoClassic.registry.createCipher, 'function');
  assert.equal(context.jscryptoClassicHashes.classicHashesPreset.kind, 'preset');
  assert.equal(typeof context.jscryptoClassicHashes.registerClassicHashes, 'function');
  context.jscryptoClassic.registry.use(context.jscryptoClassicHashes.classicHashesPreset);
  assert.equal(context.jscryptoClassic.registry.getHash('SHA256').name, 'SHA256');

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
