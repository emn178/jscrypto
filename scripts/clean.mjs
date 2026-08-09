import { rmSync } from 'node:fs';

for (const dir of [
  'packages/core/dist',
  'packages/ciphers/dist',
  'packages/modes/dist',
  'packages/paddings/dist',
  'packages/kdfs/dist',
  'packages/formats/dist',
  'packages/hashes/dist',
  'packages/suite/dist',
  'coverage',
]) {
  rmSync(dir, { recursive: true, force: true });
}
