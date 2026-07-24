import { execFileSync } from 'node:child_process';
import { readFileSync, rmSync } from 'node:fs';
import commonjs from '@rollup/plugin-commonjs';
import { nodeResolve } from '@rollup/plugin-node-resolve';
import terser from '@rollup/plugin-terser';
import { rollup } from 'rollup';
import ts from 'typescript';

const year = '2026';
const owner = 'Chen, Yi-Cyuan';
const globals = {
  '@jscrypto/core': 'jscryptoCore',
};

const packages = [
  {
    name: '@jscrypto/core',
    displayName: 'jscrypto-core',
    globalName: 'jscryptoCore',
    entryPoint: 'packages/core/src/index.ts',
    packageJson: 'packages/core/package.json',
    distDir: 'packages/core/dist',
    externals: [],
  },
  {
    name: '@jscrypto/classic',
    displayName: 'jscrypto-classic',
    globalName: 'jscryptoClassic',
    entryPoint: 'packages/classic/src/index.ts',
    packageJson: 'packages/classic/package.json',
    distDir: 'packages/classic/dist',
    externals: ['@jscrypto/core'],
  },
];

for (const pkg of packages) {
  rmSync(pkg.distDir, { recursive: true, force: true });
}

rmSync('tsconfig.tsbuildinfo', { force: true });

execFileSync(process.execPath, ['node_modules/typescript/bin/tsc', '-b'], {
  stdio: 'inherit',
  shell: false,
});

for (const pkg of packages) {
  rmSync(`${pkg.distDir}/.tsbuildinfo`, { force: true });
  rmSync('tsconfig.tsbuildinfo', { force: true });
  await buildPackage(pkg);
}

await buildHashesPackage();

/**
 * @param {{
 *   name: string,
 *   displayName: string,
 *   globalName: string,
 *   entryPoint: string,
 *   packageJson: string,
 *   distDir: string,
 *   externals: string[],
 * }} pkg
 */
async function buildPackage(pkg) {
  const banner = licenseBanner(pkg.name, pkg.packageJson);

  await buildEntry({
    input: pkg.entryPoint,
    external: pkg.externals,
    outputs: [
      {
        file: `${pkg.distDir}/index.mjs`,
        format: 'esm',
      },
      {
        file: `${pkg.distDir}/index.cjs`,
        format: 'cjs',
        exports: 'named',
      },
    ],
  }, banner);

  await buildEntry({
    input: pkg.entryPoint,
    external: pkg.externals,
    browser: true,
    globals,
    outputs: [
      {
        file: `${pkg.distDir}/${pkg.displayName}.iife.js`,
        format: 'iife',
        name: pkg.globalName,
      },
      {
        file: `${pkg.distDir}/${pkg.displayName}.iife.min.js`,
        format: 'iife',
        name: pkg.globalName,
        minify: true,
      },
      {
        file: `${pkg.distDir}/${pkg.displayName}.umd.js`,
        format: 'umd',
        name: pkg.globalName,
      },
      {
        file: `${pkg.distDir}/${pkg.displayName}.umd.min.js`,
        format: 'umd',
        name: pkg.globalName,
        minify: true,
      },
    ],
  }, banner);
}

async function buildHashesPackage() {
  const entryPoint = 'packages/classic/src/hashes-entry.ts';
  const distDir = 'packages/classic/dist';
  const banner = licenseBanner('@jscrypto/classic hashes', 'packages/classic/package.json');
  const nodeExternals = [
    '@jscrypto/core',
    'js-md5',
    'js-sha1',
    'js-sha256',
    'js-sha3',
    'js-sha512',
  ];

  await buildEntry({
    input: entryPoint,
    external: nodeExternals,
    outputs: [
      {
        file: `${distDir}/hashes.mjs`,
        format: 'esm',
      },
      {
        file: `${distDir}/hashes.cjs`,
        format: 'cjs',
        exports: 'named',
      },
    ],
  }, banner);

  await buildEntry({
    input: entryPoint,
    external: ['@jscrypto/core'],
    browser: true,
    globals,
    outputs: [
      {
        file: `${distDir}/jscrypto-classic-hashes.iife.min.js`,
        format: 'iife',
        name: 'jscryptoClassicHashes',
        minify: true,
      },
    ],
  }, banner);
}

/**
 * @param {{
 *   input: string,
 *   external: string[],
 *   browser?: boolean,
 *   globals?: Record<string, string>,
 *   outputs: Array<{
 *     file: string,
 *     format: 'esm' | 'cjs' | 'iife' | 'umd',
 *     name?: string,
 *     exports?: 'named',
 *     minify?: boolean,
 *   }>,
 * }} options
 * @param {string} banner
 */
async function buildEntry(options, banner) {
  const bundle = await rollup({
    input: options.input,
    external: options.external,
    plugins: [
      resolveTypeScriptExtensions(),
      transpileTypeScript(),
      nodeResolve(
        options.browser
          ? { browser: true, preferBuiltins: false }
          : undefined,
      ),
      commonjs(),
    ],
  });

  try {
    for (const output of options.outputs) {
      const plugins = output.minify
        ? [
            terser({
              format: {
                comments: /^!/,
              },
            }),
          ]
        : [];

      await bundle.write({
        banner,
        file: output.file,
        format: output.format,
        name: output.name,
        exports: output.exports,
        globals: options.globals,
        sourcemap: true,
        plugins,
      });
    }
  } finally {
    await bundle.close();
  }
}

/**
 * @param {string} name
 * @param {string} packageJsonPath
 */
function licenseBanner(name, packageJsonPath) {
  const version = JSON.parse(readFileSync(packageJsonPath, 'utf8')).version;
  return `/*!
 * ${name} v${version}
 * Copyright ${year} ${owner}
 * Released under the MIT license
 */`;
}

function resolveTypeScriptExtensions() {
  return {
    name: 'resolve-typescript-extensions',
    /**
     * @param {string} source
     * @param {string | undefined} importer
     * @param {{ skipSelf?: boolean }} options
     */
    async resolveId(source, importer, options) {
      if (!importer || !source.startsWith('.') || !source.endsWith('.js')) {
        return null;
      }

      return this.resolve(`${source.slice(0, -3)}.ts`, importer, {
        ...options,
        skipSelf: true,
      });
    },
  };
}

function transpileTypeScript() {
  return {
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
          sourceMap: true,
          inlineSources: true,
        },
      });

      return {
        code: result.outputText,
        map: result.sourceMapText ? JSON.parse(result.sourceMapText) : null,
      };
    },
  };
}
