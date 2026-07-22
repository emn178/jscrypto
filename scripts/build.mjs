import { execFileSync } from 'node:child_process';
import { readFileSync, rmSync } from 'node:fs';
import * as esbuild from 'esbuild';

const year = '2026';
const owner = 'Chen, Yi-Cyuan';

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

execFileSync(process.execPath, ['node_modules/typescript/bin/tsc', '-b'], {
  stdio: 'inherit',
  shell: false,
});

for (const pkg of packages) {
  rmSync(`${pkg.distDir}/.tsbuildinfo`, { force: true });
  await buildPackage(pkg);
}

await buildHashesPackage();

async function buildPackage(pkg) {
  const version = readPackageVersion(pkg.packageJson);
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

async function buildHashesPackage() {
  const entryPoint = 'packages/classic/src/hashes-entry.ts';
  const distDir = 'packages/classic/dist';
  const version = readPackageVersion('packages/classic/package.json');
  const nodeExternals = [
    '@jscrypto/core',
    'js-md5',
    'js-sha1',
    'js-sha256',
    'js-sha3',
    'js-sha512',
  ];
  const banner = `/*!
 * @jscrypto/classic hashes v${version}
 * Copyright ${year} ${owner}
 * Released under the MIT license
 */`;
  const commonOptions = {
    entryPoints: [entryPoint],
    bundle: true,
    sourcemap: true,
    banner: { js: banner },
    target: 'es2015',
    logLevel: 'info',
  };

  await esbuild.build({
    ...commonOptions,
    format: 'esm',
    external: nodeExternals,
    outfile: `${distDir}/hashes.mjs`,
  });
  await esbuild.build({
    ...commonOptions,
    format: 'cjs',
    platform: 'node',
    external: nodeExternals,
    outfile: `${distDir}/hashes.cjs`,
  });
  await esbuild.build({
    ...commonOptions,
    format: 'iife',
    globalName: 'jscryptoClassicHashes',
    minify: true,
    outfile: `${distDir}/jscrypto-classic-hashes.iife.min.js`,
  });
}

function readPackageVersion(packageJsonPath) {
  const pkg = JSON.parse(readFileSync(packageJsonPath, 'utf8'));
  return pkg.version;
}
