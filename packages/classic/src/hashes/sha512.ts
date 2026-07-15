import { createHash } from './component.js';
import { sha512Hash } from './native.js';

export const sha512 = createHash('SHA512', 128, 64, sha512Hash);
