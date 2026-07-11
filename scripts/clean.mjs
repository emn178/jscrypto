import { rmSync } from 'node:fs';

for (const dir of ['packages/core/dist', 'packages/classic/dist', 'coverage']) {
  rmSync(dir, { recursive: true, force: true });
}
