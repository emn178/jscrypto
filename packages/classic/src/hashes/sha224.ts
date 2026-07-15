import { createHash } from './component.js';
import { sha224Hash } from './native.js';

export const sha224 = createHash('SHA224', 64, 28, sha224Hash);
