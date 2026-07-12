import { execFileSync } from 'node:child_process';
import { rmSync } from 'node:fs';
import * as esbuild from 'esbuild';

const version = '0.2.0';
const year = '2026';
const owner = 'Chen, Yi-Cyuan';

const packages = [
  {
    name: '@jscrypto/core',
    displayName: 'jscrypto-core',
    globalName: 'jscryptoCore',
    entryPoint: 'packages/core/src/index.ts',
    distDir: 'packages/core/dist',
    externals: [],
  },
  {
    name: '@jscrypto/classic',
    displayName: 'jscrypto-classic',
    globalName: 'jscryptoClassic',
    entryPoint: 'packages/classic/src/index.ts',
    distDir: 'packages/classic/dist',
    externals: ['@jscrypto/core', 'crypto-js'],
  },
];

for (const pkg of packages) {
  rmSync(pkg.distDir, { recursive: true, force: true });
}

execFileSync(process.execPath, ['node_modules/typescript/bin/tsc', '-b'], {
  stdio: 'inherit',
  shell: false,
});

for (const pkg of packages) {
  rmSync(`${pkg.distDir}/.tsbuildinfo`, { force: true });
  await buildPackage(pkg);
}

async function buildPackage(pkg) {
  const banner = `/*!
 * ${pkg.name} v${version}
 * Copyright ${year} ${owner}
 * Released under the MIT license
 */`;
  const umdFooter = `;(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.${pkg.globalName} = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  return ${pkg.globalName};
});`;
  const commonOptions = {
    entryPoints: [pkg.entryPoint],
    bundle: true,
    sourcemap: true,
    banner: {
      js: banner,
    },
    target: 'es2015',
    logLevel: 'info',
  };

  await esbuild.build({
    ...commonOptions,
    format: 'esm',
    external: pkg.externals,
    outfile: `${pkg.distDir}/index.mjs`,
  });

  await esbuild.build({
    ...commonOptions,
    format: 'cjs',
    platform: 'node',
    external: pkg.externals,
    outfile: `${pkg.distDir}/index.cjs`,
  });

  await esbuild.build({
    ...commonOptions,
    format: 'iife',
    globalName: pkg.globalName,
    outfile: `${pkg.distDir}/${pkg.displayName}.iife.js`,
  });

  await esbuild.build({
    ...commonOptions,
    format: 'iife',
    globalName: pkg.globalName,
    minify: true,
    outfile: `${pkg.distDir}/${pkg.displayName}.iife.min.js`,
  });

  await esbuild.build({
    ...commonOptions,
    format: 'iife',
    globalName: pkg.globalName,
    footer: {
      js: umdFooter,
    },
    outfile: `${pkg.distDir}/${pkg.displayName}.umd.js`,
  });

  await esbuild.build({
    ...commonOptions,
    format: 'iife',
    globalName: pkg.globalName,
    footer: {
      js: umdFooter,
    },
    minify: true,
    outfile: `${pkg.distDir}/${pkg.displayName}.umd.min.js`,
  });
}
