import { createHash } from './component.js';
import { sha3Hash } from './native.js';

export const sha3 = createHash('SHA3', 72, 64, sha3Hash);
