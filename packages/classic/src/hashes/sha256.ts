import { createHash } from './component.js';
import { sha256 as sha256Digest } from 'js-sha256';

export const sha256 = createHash('SHA256', 64, 32, (input) => new Uint8Array(sha256Digest.arrayBuffer(input)));
