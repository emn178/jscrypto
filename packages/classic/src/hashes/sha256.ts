import { createHash } from './component.js';
import { sha256Hash } from './native.js';

export const sha256 = createHash('SHA256', 64, 32, sha256Hash);
