import { createHash } from './component.js';
import { md5Hash } from './native.js';

export const md5 = createHash('MD5', 64, 16, md5Hash);
