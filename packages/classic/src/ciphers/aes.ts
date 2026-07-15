import type { BlockCipher, CipherComponent } from '@jscrypto/core';

const BLOCK_SIZE = 16;
const sbox = new Uint8Array(256);
const inverseSbox = new Uint8Array(256);

export const aes: CipherComponent<'AES'> = {
  kind: 'cipher',
  name: 'AES',
  type: 'block',
  blockSize: BLOCK_SIZE,
  keySizes: [16, 24, 32],
  create(key) {
    return createAesCipher(key);
  },
};

export function createAesCipher(key: Uint8Array): BlockCipher {
  if (key.length !== 16 && key.length !== 24 && key.length !== 32) {
    throw new Error('AES key must be 128, 192, or 256 bits.');
  }

  const roundKeys = expandKey(key);
  const rounds = key.length / 4 + 6;

  return {
    blockSize: BLOCK_SIZE,

    encryptBlock(block) {
      assertBlock(block);
      const state = new Uint8Array(block);

      addRoundKey(state, roundKeys, 0);
      for (let round = 1; round < rounds; round++) {
        substituteBytes(state, sbox);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, roundKeys, round);
      }
      substituteBytes(state, sbox);
      shiftRows(state);
      addRoundKey(state, roundKeys, rounds);

      return state;
    },

    decryptBlock(block) {
      assertBlock(block);
      const state = new Uint8Array(block);

      addRoundKey(state, roundKeys, rounds);
      for (let round = rounds - 1; round > 0; round--) {
        inverseShiftRows(state);
        substituteBytes(state, inverseSbox);
        addRoundKey(state, roundKeys, round);
        inverseMixColumns(state);
      }
      inverseShiftRows(state);
      substituteBytes(state, inverseSbox);
      addRoundKey(state, roundKeys, 0);

      return state;
    },
  };
}

initializeSboxes();

function assertBlock(block: Uint8Array): void {
  if (block.length !== BLOCK_SIZE) {
    throw new Error('AES block must be 128 bits.');
  }
}

function expandKey(key: Uint8Array): Uint8Array {
  const words = key.length / 4;
  const rounds = words + 6;
  const roundKeys = new Uint8Array(BLOCK_SIZE * (rounds + 1));
  roundKeys.set(key);

  let rcon = 1;
  const temp = new Uint8Array(4);
  for (let word = words; word < 4 * (rounds + 1); word++) {
    const offset = (word - 1) * 4;
    temp.set(roundKeys.subarray(offset, offset + 4));

    if (word % words === 0) {
      const first = temp[0];
      temp[0] = sbox[temp[1]] ^ rcon;
      temp[1] = sbox[temp[2]];
      temp[2] = sbox[temp[3]];
      temp[3] = sbox[first];
      rcon = xtime(rcon);
    } else if (words > 6 && word % words === 4) {
      for (let index = 0; index < 4; index++) {
        temp[index] = sbox[temp[index]];
      }
    }

    const previousOffset = (word - words) * 4;
    const outputOffset = word * 4;
    for (let index = 0; index < 4; index++) {
      roundKeys[outputOffset + index] = roundKeys[previousOffset + index] ^ temp[index];
    }
  }

  return roundKeys;
}

function addRoundKey(state: Uint8Array, roundKeys: Uint8Array, round: number): void {
  const offset = round * BLOCK_SIZE;
  for (let index = 0; index < BLOCK_SIZE; index++) {
    state[index] ^= roundKeys[offset + index];
  }
}

function substituteBytes(state: Uint8Array, table: Uint8Array): void {
  for (let index = 0; index < BLOCK_SIZE; index++) {
    state[index] = table[state[index]];
  }
}

function shiftRows(state: Uint8Array): void {
  const copy = new Uint8Array(state);
  state[1] = copy[5];
  state[5] = copy[9];
  state[9] = copy[13];
  state[13] = copy[1];
  state[2] = copy[10];
  state[6] = copy[14];
  state[10] = copy[2];
  state[14] = copy[6];
  state[3] = copy[15];
  state[7] = copy[3];
  state[11] = copy[7];
  state[15] = copy[11];
}

function inverseShiftRows(state: Uint8Array): void {
  const copy = new Uint8Array(state);
  state[1] = copy[13];
  state[5] = copy[1];
  state[9] = copy[5];
  state[13] = copy[9];
  state[2] = copy[10];
  state[6] = copy[14];
  state[10] = copy[2];
  state[14] = copy[6];
  state[3] = copy[7];
  state[7] = copy[11];
  state[11] = copy[15];
  state[15] = copy[3];
}

function mixColumns(state: Uint8Array): void {
  for (let offset = 0; offset < BLOCK_SIZE; offset += 4) {
    const a = state[offset];
    const b = state[offset + 1];
    const c = state[offset + 2];
    const d = state[offset + 3];
    state[offset] = xtime(a) ^ (xtime(b) ^ b) ^ c ^ d;
    state[offset + 1] = a ^ xtime(b) ^ (xtime(c) ^ c) ^ d;
    state[offset + 2] = a ^ b ^ xtime(c) ^ (xtime(d) ^ d);
    state[offset + 3] = (xtime(a) ^ a) ^ b ^ c ^ xtime(d);
  }
}

function inverseMixColumns(state: Uint8Array): void {
  for (let offset = 0; offset < BLOCK_SIZE; offset += 4) {
    const a = state[offset];
    const b = state[offset + 1];
    const c = state[offset + 2];
    const d = state[offset + 3];
    state[offset] = multiply(a, 14) ^ multiply(b, 11) ^ multiply(c, 13) ^ multiply(d, 9);
    state[offset + 1] = multiply(a, 9) ^ multiply(b, 14) ^ multiply(c, 11) ^ multiply(d, 13);
    state[offset + 2] = multiply(a, 13) ^ multiply(b, 9) ^ multiply(c, 14) ^ multiply(d, 11);
    state[offset + 3] = multiply(a, 11) ^ multiply(b, 13) ^ multiply(c, 9) ^ multiply(d, 14);
  }
}

function initializeSboxes(): void {
  for (let value = 0; value < 256; value++) {
    const inverse = value === 0 ? 0 : power(value, 254);
    const substituted = inverse
      ^ rotateLeft(inverse, 1)
      ^ rotateLeft(inverse, 2)
      ^ rotateLeft(inverse, 3)
      ^ rotateLeft(inverse, 4)
      ^ 0x63;
    sbox[value] = substituted;
    inverseSbox[substituted] = value;
  }
}

function power(value: number, exponent: number): number {
  let result = 1;
  let factor = value;
  while (exponent > 0) {
    if (exponent & 1) {
      result = multiply(result, factor);
    }
    factor = multiply(factor, factor);
    exponent >>>= 1;
  }
  return result;
}

function rotateLeft(value: number, bits: number): number {
  return ((value << bits) | (value >>> (8 - bits))) & 0xff;
}

function xtime(value: number): number {
  return ((value << 1) ^ ((value >>> 7) * 0x11b)) & 0xff;
}

function multiply(left: number, right: number): number {
  let product = 0;
  let factor = left;
  let multiplier = right;
  while (multiplier > 0) {
    if (multiplier & 1) {
      product ^= factor;
    }
    factor = xtime(factor);
    multiplier >>>= 1;
  }
  return product;
}
