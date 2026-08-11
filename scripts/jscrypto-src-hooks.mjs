import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const PACKAGE_NAMES = new Set([
  'core',
  'ciphers',
  'modes',
  'paddings',
  'kdfs',
  'formats',
  'hashes',
  'suite',
]);

/**
 * Map @jscrypto/* package imports to TypeScript source during source tests.
 * Mirrors public package subpaths and prefers *-node.ts when the "node"
 * condition is present and that file exists.
 */
function resolveJscryptoSource(specifier, conditions) {
  const match = /^@jscrypto\/([^/]+)(?:\/(.*))?$/.exec(specifier);
  if (!match) {
    return null;
  }

  const [, packageName, subpath] = match;
  if (!PACKAGE_NAMES.has(packageName)) {
    return null;
  }

  if (subpath === 'browser' || subpath === 'umd' || /\/(browser|umd)$/.test(subpath ?? '')) {
    return null;
  }

  const srcDir = path.join(ROOT, 'packages', packageName, 'src');
  const preferNode = Array.isArray(conditions) && conditions.includes('node');

  if (!subpath) {
    if (preferNode) {
      const nodeEntry = path.join(srcDir, 'index-node.ts');
      if (existsSync(nodeEntry)) {
        return nodeEntry;
      }
    }
    return path.join(srcDir, 'index.ts');
  }

  if (preferNode) {
    const nodeVariant = path.join(srcDir, `${subpath}-node.ts`);
    if (existsSync(nodeVariant)) {
      return nodeVariant;
    }
  }

  const sourceFile = path.join(srcDir, `${subpath}.ts`);
  if (existsSync(sourceFile)) {
    return sourceFile;
  }

  return null;
}

export async function resolve(specifier, context, nextResolve) {
  if (specifier.startsWith('@jscrypto/')) {
    const mapped = resolveJscryptoSource(specifier, context.conditions);
    if (mapped) {
      // Delegate to the next resolver (tsx) so .ts files are still transpiled.
      return nextResolve(pathToFileURL(mapped).href, context);
    }
  }

  return nextResolve(specifier, context);
}
