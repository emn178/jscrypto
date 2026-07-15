import { createHash } from './component.js';
import * as sha3Module from 'js-sha3';

const keccak512Digest = (sha3Module as unknown as { default: typeof import('js-sha3') }).default.keccak512;
const hashKeccak512 = (input: Uint8Array): Uint8Array => new Uint8Array(keccak512Digest.arrayBuffer(input));

export const keccak512 = createHash('KECCAK512', 72, 64, hashKeccak512);

/**
 * @deprecated CryptoJS-compatible SHA3 is Keccak-512. Use `keccak512` / `KECCAK512` instead.
 */
export const sha3 = createHash('SHA3', 72, 64, hashKeccak512);
