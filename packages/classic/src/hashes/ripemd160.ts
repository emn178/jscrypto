import { createHash } from './component.js';
import { ripemd160 as ripemd160Digest } from '@noble/hashes/legacy.js';

export const ripemd160 = createHash('RIPEMD160', 64, 20, ripemd160Digest);
