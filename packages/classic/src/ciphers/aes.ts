import type { BlockCipher, CipherComponent } from '@jscrypto/core';

const BLOCK_SIZE = 16;
const sbox = new Uint8Array(256);
const inverseSbox = new Uint8Array(256);
const encTable0 = new Uint32Array(256);
const encTable1 = new Uint32Array(256);
const encTable2 = new Uint32Array(256);
const encTable3 = new Uint32Array(256);
const decTable0 = new Uint32Array(256);
const decTable1 = new Uint32Array(256);
const decTable2 = new Uint32Array(256);
const decTable3 = new Uint32Array(256);
const rcon = new Uint8Array([0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]);

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

  const { decryptKeys, encryptKeys, rounds } = expandKey(key);
  return {
    blockSize: BLOCK_SIZE,

    encrypt(input, output) {
      return cryptBlocks(input, output, encryptKeys, rounds, sbox, encTable0, encTable1, encTable2, encTable3);
    },

    decrypt(input, output) {
      return cryptBlocks(input, output, decryptKeys, rounds, inverseSbox, decTable0, decTable1, decTable2, decTable3, true);
    },
  };
}

initializeTables();

function assertBlocks(input: Uint8Array, output: Uint8Array): void {
  if (input.length % BLOCK_SIZE !== 0) {
    throw new Error('AES input length must be a multiple of 128 bits.');
  }
  if (output.length !== input.length) {
    throw new Error('AES output length must equal input length.');
  }
}

function expandKey(key: Uint8Array): { encryptKeys: Uint32Array; decryptKeys: Uint32Array; rounds: number } {
  const words = key.length / 4;
  const rounds = words + 6;
  const rows = (rounds + 1) * 4;
  const encryptKeys = new Uint32Array(rows);
  const decryptKeys = new Uint32Array(rows);

  for (let row = 0; row < rows; row++) {
    if (row < words) {
      encryptKeys[row] = wordFromBytes(key, row * 4);
      continue;
    }

    let temp = encryptKeys[row - 1];
    if (row % words === 0) {
      temp = subWord((temp << 8) | (temp >>> 24)) ^ (rcon[(row / words) | 0] << 24);
    } else if (words > 6 && row % words === 4) {
      temp = subWord(temp);
    }
    encryptKeys[row] = encryptKeys[row - words] ^ temp;
  }

  for (let inverseRow = 0; inverseRow < rows; inverseRow++) {
    const row = rows - inverseRow;
    const key = inverseRow % 4 ? encryptKeys[row] : encryptKeys[row - 4];
    decryptKeys[inverseRow] = inverseRow < 4 || row <= 4
      ? key
      : decTable0[sbox[key >>> 24]]
        ^ decTable1[sbox[(key >>> 16) & 0xff]]
        ^ decTable2[sbox[(key >>> 8) & 0xff]]
        ^ decTable3[sbox[key & 0xff]];
  }

  return { decryptKeys, encryptKeys, rounds };
}

function cryptBlocks(
  input: Uint8Array,
  output: Uint8Array,
  keys: Uint32Array,
  rounds: number,
  box: Uint8Array,
  table0: Uint32Array,
  table1: Uint32Array,
  table2: Uint32Array,
  table3: Uint32Array,
  swapRows = false
): Uint8Array {
  assertBlocks(input, output);
  const view = new DataView(input.buffer, input.byteOffset, input.byteLength);
  const outputView = new DataView(output.buffer, output.byteOffset, output.byteLength);
  let o1 = 4;
  let o3 = 12;
  if (swapRows) {
    o1 = 12;
    o3 = 4;
  }
  for (let offset = 0; offset < input.length; offset += BLOCK_SIZE) {
    let off1 = offset + o1;
    let off2 = offset + 8;
    let off3 = offset + o3;
    let w0 = view.getUint32(offset, false);
    let w1 = view.getUint32(off1, false);
    let w2 = view.getUint32(off2, false);
    let w3 = view.getUint32(off3, false);

    let s0 = w0 ^ keys[0];
    let s1 = w1 ^ keys[1];
    let s2 = w2 ^ keys[2];
    let s3 = w3 ^ keys[3];
    let keyIndex = 4;

    for (let round = 1; round < rounds; round++) {
      const t0 = table0[s0 >>> 24] ^ table1[(s1 >>> 16) & 0xff] ^ table2[(s2 >>> 8) & 0xff] ^ table3[s3 & 0xff] ^ keys[keyIndex++];
      const t1 = table0[s1 >>> 24] ^ table1[(s2 >>> 16) & 0xff] ^ table2[(s3 >>> 8) & 0xff] ^ table3[s0 & 0xff] ^ keys[keyIndex++];
      const t2 = table0[s2 >>> 24] ^ table1[(s3 >>> 16) & 0xff] ^ table2[(s0 >>> 8) & 0xff] ^ table3[s1 & 0xff] ^ keys[keyIndex++];
      const t3 = table0[s3 >>> 24] ^ table1[(s0 >>> 16) & 0xff] ^ table2[(s1 >>> 8) & 0xff] ^ table3[s2 & 0xff] ^ keys[keyIndex++];
      s0 = t0;
      s1 = t1;
      s2 = t2;
      s3 = t3;
    }

    let output0 = ((box[s0 >>> 24] << 24) | (box[(s1 >>> 16) & 0xff] << 16) | (box[(s2 >>> 8) & 0xff] << 8) | box[s3 & 0xff]) ^ keys[keyIndex++];
    let output1 = ((box[s1 >>> 24] << 24) | (box[(s2 >>> 16) & 0xff] << 16) | (box[(s3 >>> 8) & 0xff] << 8) | box[s0 & 0xff]) ^ keys[keyIndex++];
    let output2 = ((box[s2 >>> 24] << 24) | (box[(s3 >>> 16) & 0xff] << 16) | (box[(s0 >>> 8) & 0xff] << 8) | box[s1 & 0xff]) ^ keys[keyIndex++];
    let output3 = ((box[s3 >>> 24] << 24) | (box[(s0 >>> 16) & 0xff] << 16) | (box[(s1 >>> 8) & 0xff] << 8) | box[s2 & 0xff]) ^ keys[keyIndex];
  
    outputView.setUint32(offset, output0, false);
    outputView.setUint32(off1, output1, false);
    outputView.setUint32(off2, output2, false);
    outputView.setUint32(off3, output3, false);
  }
  return output;
}

function initializeTables(): void {
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

  const doubles = new Uint16Array(256);
  for (let value = 0; value < 256; value++) {
    doubles[value] = xtime(value);
  }

  for (let value = 0; value < 256; value++) {
    const substituted = sbox[value];
    const x2 = doubles[value];
    const x4 = doubles[x2];
    const x8 = doubles[x4];

    let table = (doubles[substituted] * 0x101) ^ (substituted * 0x1010100);
    encTable0[value] = (table << 24) | (table >>> 8);
    encTable1[value] = (table << 16) | (table >>> 16);
    encTable2[value] = (table << 8) | (table >>> 24);
    encTable3[value] = table;

    table = (x8 * 0x1010101) ^ (x4 * 0x10001) ^ (x2 * 0x101) ^ (value * 0x1010100);
    decTable0[substituted] = (table << 24) | (table >>> 8);
    decTable1[substituted] = (table << 16) | (table >>> 16);
    decTable2[substituted] = (table << 8) | (table >>> 24);
    decTable3[substituted] = table;
  }
}

function subWord(word: number): number {
  return (sbox[word >>> 24] << 24)
    | (sbox[(word >>> 16) & 0xff] << 16)
    | (sbox[(word >>> 8) & 0xff] << 8)
    | sbox[word & 0xff];
}

function wordFromBytes(bytes: Uint8Array, offset: number): number {
  return (bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3];
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
