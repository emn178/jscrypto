import { createHash } from './component.js';
import { ripemd160Hash } from './native.js';

export const ripemd160 = createHash('RIPEMD160', 64, 20, ripemd160Hash);
