import { createHash } from './component.js';
import { sha384 as sha384Digest } from 'js-sha512';

export const sha384 = createHash('SHA384', 128, 48, (input) => new Uint8Array(sha384Digest.arrayBuffer(input)));
