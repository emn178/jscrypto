import { createHash } from './component.js';
import { sha1Hash } from './native.js';

export const sha1 = createHash('SHA1', 64, 20, sha1Hash);
