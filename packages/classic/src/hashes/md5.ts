import { createHash } from './component.js';
import { md5 as md5Digest } from 'js-md5';

export const md5 = createHash('MD5', 64, 16, (input) => new Uint8Array(md5Digest.arrayBuffer(input)));
