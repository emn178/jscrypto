import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DEFAULT_ROOTS = [path.join(ROOT, 'packages')];

/**
 * Collect package-local *.test.ts files.
 * Optional argv entries limit the search to specific directories.
 */
function collectTestFiles(roots) {
  const files = [];

  function walk(dir) {
    if (!existsSync(dir)) {
      return;
    }

    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(fullPath);
        continue;
      }
      if (entry.isFile() && entry.name.endsWith('.test.ts')) {
        files.push(fullPath);
      }
    }
  }

  for (const root of roots) {
    const absoluteRoot = path.resolve(ROOT, root);
    const testDir = path.join(absoluteRoot, 'test');
    if (existsSync(testDir) && path.basename(absoluteRoot) !== 'test') {
      walk(testDir);
    } else {
      walk(absoluteRoot);
    }
  }

  return files.sort();
}

function supportsImportFlag(version) {
  const [major, minor] = version.split('.').map(Number);
  return major > 18 || (major === 18 && minor >= 19);
}

if (!supportsImportFlag(process.versions.node)) {
  console.error(
    `test:src requires Node.js >= 18.19 (for --import with tsx). Current: ${process.version}`,
  );
  process.exit(1);
}

const requestedRoots = process.argv.slice(2);
const roots = requestedRoots.length > 0 ? requestedRoots : DEFAULT_ROOTS;
const tests = collectTestFiles(roots);

if (tests.length === 0) {
  console.error('No package-local *.test.ts files found.');
  process.exit(1);
}

const registerPath = path.join(ROOT, 'scripts', 'register-jscrypto-src.mjs');
const args = ['--import', 'tsx', '--import', registerPath, '--test', ...tests];

const result = spawnSync(process.execPath, args, {
  cwd: ROOT,
  stdio: 'inherit',
  env: process.env,
});

if (result.error) {
  console.error(result.error);
  process.exit(1);
}

process.exit(result.status ?? 1);
