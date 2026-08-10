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
  '@jscrypto/ciphers': 'jscryptoCiphers',
  '@jscrypto/formats': 'jscryptoFormats',
  '@jscrypto/hashes': 'jscryptoHashes',
  '@jscrypto/kdfs': 'jscryptoKdfs',
  '@jscrypto/modes': 'jscryptoModes',
  '@jscrypto/paddings': 'jscryptoPaddings',
  '@jscrypto/suite/basic': 'jscryptoSuiteBasic',
  '@jscrypto/suite/all': 'jscryptoSuiteAll',
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
    name: '@jscrypto/ciphers',
    displayName: 'jscrypto-ciphers',
    globalName: 'jscryptoCiphers',
    entryPoint: 'packages/ciphers/src/index.ts',
    nodeEntryPoint: 'packages/ciphers/src/index-node.ts',
    packageJson: 'packages/ciphers/package.json',
    distDir: 'packages/ciphers/dist',
    externals: ['@jscrypto/core'],
    browserExternals: ['@jscrypto/core'],
    nodeExternals: ['node:crypto'],
    subEntries: [
      {
        name: 'aes',
        displayName: 'jscrypto-ciphers-aes',
        globalName: 'jscryptoCiphersAes',
        entryPoint: 'packages/ciphers/src/aes.ts',
        nodeEntryPoint: 'packages/ciphers/src/aes-node.ts',
      },
      {
        name: 'aes-ccm-aad',
        entryPoint: 'packages/ciphers/src/aes-ccm-aad.ts',
      },
      {
        name: 'des',
        displayName: 'jscrypto-ciphers-des',
        globalName: 'jscryptoCiphersDes',
        entryPoint: 'packages/ciphers/src/des.ts',
      },
      {
        name: 'chacha20',
        displayName: 'jscrypto-ciphers-chacha20',
        globalName: 'jscryptoCiphersChacha20',
        entryPoint: 'packages/ciphers/src/chacha20.ts',
      },
      {
        name: 'rc4',
        displayName: 'jscrypto-ciphers-rc4',
        globalName: 'jscryptoCiphersRc4',
        entryPoint: 'packages/ciphers/src/rc4.ts',
      },
      {
        name: 'speck',
        displayName: 'jscrypto-ciphers-speck',
        globalName: 'jscryptoCiphersSpeck',
        entryPoint: 'packages/ciphers/src/speck.ts',
      },
      {
        name: 'triple-des',
        displayName: 'jscrypto-ciphers-triple-des',
        globalName: 'jscryptoCiphersTripleDes',
        entryPoint: 'packages/ciphers/src/triple-des.ts',
      },
    ],
  },
  {
    name: '@jscrypto/modes',
    displayName: 'jscrypto-modes',
    globalName: 'jscryptoModes',
    entryPoint: 'packages/modes/src/index.ts',
    packageJson: 'packages/modes/package.json',
    distDir: 'packages/modes/dist',
    externals: ['@jscrypto/core'],
    subEntries: ['cbc', 'cfb', 'ctr', 'ecb', 'gcm', 'ofb'].map((name) => ({
      name,
      displayName: `jscrypto-modes-${name}`,
      globalName: `jscryptoModes${toPascalCase(name)}`,
      entryPoint: `packages/modes/src/${name}.ts`,
    })),
  },
  {
    name: '@jscrypto/paddings',
    displayName: 'jscrypto-paddings',
    globalName: 'jscryptoPaddings',
    entryPoint: 'packages/paddings/src/index.ts',
    packageJson: 'packages/paddings/package.json',
    distDir: 'packages/paddings/dist',
    externals: ['@jscrypto/core'],
    subEntries: ['ansi-x923', 'iso10126', 'iso97971', 'none', 'pkcs5', 'pkcs7', 'zero'].map((name) => ({
      name,
      displayName: `jscrypto-paddings-${name}`,
      globalName: `jscryptoPaddings${toPascalCase(name)}`,
      entryPoint: `packages/paddings/src/${name}.ts`,
    })),
  },
  {
    name: '@jscrypto/kdfs',
    displayName: 'jscrypto-kdfs',
    globalName: 'jscryptoKdfs',
    entryPoint: 'packages/kdfs/src/index.ts',
    packageJson: 'packages/kdfs/package.json',
    distDir: 'packages/kdfs/dist',
    externals: ['@jscrypto/core'],
    subEntries: ['argon2', 'evpkdf', 'hkdf', 'pbkdf2', 'scrypt'].map((name) => ({
      name,
      displayName: `jscrypto-kdfs-${name}`,
      globalName: `jscryptoKdfs${toPascalCase(name)}`,
      entryPoint: `packages/kdfs/src/${name}.ts`,
    })),
  },
  {
    name: '@jscrypto/formats',
    displayName: 'jscrypto-formats',
    globalName: 'jscryptoFormats',
    entryPoint: 'packages/formats/src/index.ts',
    packageJson: 'packages/formats/package.json',
    distDir: 'packages/formats/dist',
    externals: ['@jscrypto/core'],
    subEntries: ['openssl'].map((name) => ({
      name,
      displayName: `jscrypto-formats-${name}`,
      globalName: `jscryptoFormats${toPascalCase(name)}`,
      entryPoint: `packages/formats/src/${name}.ts`,
    })),
  },
  {
    name: '@jscrypto/hashes',
    displayName: 'jscrypto-hashes',
    globalName: 'jscryptoHashes',
    entryPoint: 'packages/hashes/src/index.ts',
    packageJson: 'packages/hashes/package.json',
    distDir: 'packages/hashes/dist',
    externals: [
      '@jscrypto/core',
      'js-md5',
      'js-sha1',
      'js-sha256',
      'js-sha3',
      'js-sha512',
    ],
    browserExternals: ['@jscrypto/core'],
    subEntries: ['md5', 'ripemd160', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha3'].map((name) => ({
      name,
      displayName: `jscrypto-hashes-${name}`,
      globalName: `jscryptoHashes${toPascalCase(name)}`,
      entryPoint: `packages/hashes/src/${name}.ts`,
    })),
  },
  {
    name: '@jscrypto/suite',
    displayName: 'jscrypto-suite',
    globalName: 'jscryptoSuite',
    entryPoint: 'packages/suite/src/index.ts',
    nodeEntryPoint: 'packages/suite/src/index.ts',
    browserEntryPoint: 'packages/suite/src/basic.ts',
    packageJson: 'packages/suite/package.json',
    distDir: 'packages/suite/dist',
    externals: [
      '@jscrypto/core',
      '@jscrypto/ciphers',
      '@jscrypto/formats',
      '@jscrypto/hashes',
      '@jscrypto/kdfs',
      '@jscrypto/modes',
      '@jscrypto/paddings',
    ],
    browserExternals: ['@jscrypto/core'],
    subEntries: [
      {
        name: 'basic',
        entryPoint: 'packages/suite/src/basic.ts',
      },
      {
        name: 'all',
        entryPoint: 'packages/suite/src/all.ts',
      },
    ],
    browserEntries: [
      {
        name: 'basic',
        displayName: 'jscrypto-suite-basic',
        globalName: 'jscryptoSuiteBasic',
        entryPoint: 'packages/suite/src/basic.ts',
      },
      {
        name: 'all',
        displayName: 'jscrypto-suite-all',
        globalName: 'jscryptoSuiteAll',
        entryPoint: 'packages/suite/src/all.ts',
      },
    ],
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

/**
 * @param {{
 *   name: string,
 *   displayName: string,
 *   globalName: string,
 *   entryPoint: string,
 *   nodeEntryPoint?: string,
 *   browserEntryPoint?: string,
 *   packageJson: string,
 *   distDir: string,
 *   externals: string[],
 *   browserExternals?: string[],
 *   nodeExternals?: string[],
 *   subEntries?: Array<{ name: string, entryPoint: string, nodeEntryPoint?: string, displayName?: string, globalName?: string }>,
 *   browserEntries?: Array<{ name: string, displayName: string, globalName: string, entryPoint: string }>,
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

  if (pkg.nodeEntryPoint) {
    await buildEntry({
      input: pkg.nodeEntryPoint,
      external: [...pkg.externals, ...(pkg.nodeExternals || [])],
      outputs: [
        {
          file: `${pkg.distDir}/index.node.mjs`,
          format: 'esm',
        },
        {
          file: `${pkg.distDir}/index.node.cjs`,
          format: 'cjs',
          exports: 'named',
        },
      ],
    }, banner);
  }

  if (pkg.subEntries) {
    for (const entry of pkg.subEntries) {
      await buildEntry({
        input: entry.entryPoint,
        external: pkg.externals,
        outputs: [
          {
            file: `${pkg.distDir}/${entry.name}.mjs`,
            format: 'esm',
          },
          {
            file: `${pkg.distDir}/${entry.name}.cjs`,
            format: 'cjs',
            exports: 'named',
          },
        ],
      }, banner);

      if (entry.nodeEntryPoint) {
        await buildEntry({
          input: entry.nodeEntryPoint,
          external: [...pkg.externals, ...(pkg.nodeExternals || [])],
          outputs: [
            {
              file: `${pkg.distDir}/${entry.name}.node.mjs`,
              format: 'esm',
            },
            {
              file: `${pkg.distDir}/${entry.name}.node.cjs`,
              format: 'cjs',
              exports: 'named',
            },
          ],
        }, banner);
      }

      if (entry.displayName && entry.globalName) {
        await buildEntry({
          input: entry.entryPoint,
          external: pkg.browserExternals || pkg.externals,
          browser: true,
          globals,
          outputs: [
            {
              file: `${pkg.distDir}/${entry.displayName}.iife.js`,
              format: 'iife',
              name: entry.globalName,
            },
            {
              file: `${pkg.distDir}/${entry.displayName}.iife.min.js`,
              format: 'iife',
              name: entry.globalName,
              minify: true,
            },
            {
              file: `${pkg.distDir}/${entry.displayName}.umd.js`,
              format: 'umd',
              name: entry.globalName,
            },
            {
              file: `${pkg.distDir}/${entry.displayName}.umd.min.js`,
              format: 'umd',
              name: entry.globalName,
              minify: true,
            },
          ],
        }, banner);
      }
    }
  }

  await buildEntry({
    input: pkg.browserEntryPoint || pkg.entryPoint,
    external: pkg.browserExternals || pkg.externals,
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

  if (pkg.browserEntries) {
    for (const entry of pkg.browserEntries) {
      await buildEntry({
        input: entry.entryPoint,
        external: pkg.browserExternals || pkg.externals,
        browser: true,
        globals,
        outputs: [
          {
            file: `${pkg.distDir}/${entry.displayName}.iife.js`,
            format: 'iife',
            name: entry.globalName,
          },
          {
            file: `${pkg.distDir}/${entry.displayName}.iife.min.js`,
            format: 'iife',
            name: entry.globalName,
            minify: true,
          },
          {
            file: `${pkg.distDir}/${entry.displayName}.umd.js`,
            format: 'umd',
            name: entry.globalName,
          },
          {
            file: `${pkg.distDir}/${entry.displayName}.umd.min.js`,
            format: 'umd',
            name: entry.globalName,
            minify: true,
          },
        ],
      }, banner);
    }
  }
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

function toPascalCase(value) {
  return value
    .split('-')
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join('');
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
