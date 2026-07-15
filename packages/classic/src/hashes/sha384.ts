import { createHash } from './component.js';
import { sha384Hash } from './native.js';

export const sha384 = createHash('SHA384', 128, 48, sha384Hash);
