import { createHash } from './component.js';
import { sha224 as sha224Digest } from 'js-sha256';

export const sha224 = createHash('SHA224', 64, 28, (input) => new Uint8Array(sha224Digest.arrayBuffer(input)));
