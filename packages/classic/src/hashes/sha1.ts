import { createHash } from './component.js';
import { sha1 as sha1Digest } from 'js-sha1';

export const sha1 = createHash('SHA1', 64, 20, (input) => new Uint8Array(sha1Digest.arrayBuffer(input)));
