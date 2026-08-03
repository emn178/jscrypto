import type { BlockCipher, CipherComponent } from '@jscrypto/core';

export const des: CipherComponent<'DES'> = {
  kind: 'cipher',
  name: 'DES',
  type: 'block',
  blockSize: 8,
  keySizes: [8],
  create(key) {
    return createDesCipher(key);
  },
};

export function createDesCipher(key: Uint8Array): BlockCipher {
  if (key.length !== 8) {
    throw new Error('DES key must be 64 bits.');
  }

  const subkeys = createSubkeys(key);
  const tmp = [0, 0];

  return {
    blockSize: 8,

    encryptBlock(input, inputOffset, output, outputOffset) {
      processBlock(input, inputOffset, output, outputOffset, subkeys, tmp, true);
    },

    decryptBlock(input, inputOffset, output, outputOffset) {
      processBlock(input, inputOffset, output, outputOffset, subkeys, tmp, false);
    },

    encrypt(input, output) {
      return processBlocks(input, output, subkeys, true, 'DES');
    },

    decrypt(input, output) {
      return processBlocks(input, output, subkeys, false, 'DES');
    },
  };
}

function processBlocks(
  input: Uint8Array,
  output: Uint8Array,
  subkeys: readonly number[],
  encrypting: boolean,
  name: string,
): Uint8Array {
  assertBlocks(input, output, name);
  const tmp = [0, 0];
  for (let offset = 0; offset < input.length; offset += 8) {
    processBlock(input, offset, output, offset, subkeys, tmp, encrypting);
  }
  return output;
}

function createSubkeys(key: Uint8Array): number[] {
  const subkeys = new Array<number>(32);
  let keyLeft = readUint32BE(key, 0);
  let keyRight = readUint32BE(key, 4);
  const tmp = [0, 0];

  permutedChoice1(keyLeft, keyRight, tmp, 0);
  keyLeft = tmp[0];
  keyRight = tmp[1];

  for (let index = 0; index < subkeys.length; index += 2) {
    const shift = KEY_SHIFTS[index >>> 1];
    keyLeft = rotateLeft28(keyLeft, shift);
    keyRight = rotateLeft28(keyRight, shift);
    permutedChoice2(keyLeft, keyRight, subkeys, index);
  }

  return subkeys;
}

function processBlock(
  input: Uint8Array,
  inputOffset: number,
  output: Uint8Array,
  outputOffset: number,
  subkeys: readonly number[],
  tmp: number[],
  encrypting: boolean,
): void {
  let left = readUint32BE(input, inputOffset);
  let right = readUint32BE(input, inputOffset + 4);

  initialPermutation(left, right, tmp, 0);
  left = tmp[0];
  right = tmp[1];

  if (encrypting) {
    for (let index = 0; index < subkeys.length; index += 2) {
      const nextLeft = right;
      right = (left ^ feistel(right, subkeys[index], subkeys[index + 1], tmp)) >>> 0;
      left = nextLeft;
    }
    reverseInitialPermutation(right, left, tmp, 0);
  } else {
    const originalLeft = left;
    left = right;
    right = originalLeft;
    for (let index = subkeys.length - 2; index >= 0; index -= 2) {
      const nextLeft = left;
      left = (right ^ feistel(left, subkeys[index], subkeys[index + 1], tmp)) >>> 0;
      right = nextLeft;
    }
    reverseInitialPermutation(left, right, tmp, 0);
  }

  writeUint32BE(output, tmp[0], outputOffset);
  writeUint32BE(output, tmp[1], outputOffset + 4);
}

function feistel(right: number, keyLeft: number, keyRight: number, tmp: number[]): number {
  expand(right, tmp, 0);
  return permute(substitute((keyLeft ^ tmp[0]) >>> 0, (keyRight ^ tmp[1]) >>> 0));
}

function readUint32BE(bytes: Uint8Array, offset: number): number {
  return (
    (bytes[offset] << 24)
    | (bytes[offset + 1] << 16)
    | (bytes[offset + 2] << 8)
    | bytes[offset + 3]
  ) >>> 0;
}

function writeUint32BE(bytes: Uint8Array, value: number, offset: number): void {
  bytes[offset] = value >>> 24;
  bytes[offset + 1] = value >>> 16;
  bytes[offset + 2] = value >>> 8;
  bytes[offset + 3] = value;
}

// Word-based DES helpers adapted from des.js (MIT, Fedor Indutny).
function initialPermutation(inputLeft: number, inputRight: number, output: number[], offset: number): void {
  let outputLeft = 0;
  let outputRight = 0;

  for (let bit = 6; bit >= 0; bit -= 2) {
    for (let shift = 0; shift <= 24; shift += 8) {
      outputLeft = (outputLeft << 1) | ((inputRight >>> (shift + bit)) & 1);
    }
    for (let shift = 0; shift <= 24; shift += 8) {
      outputLeft = (outputLeft << 1) | ((inputLeft >>> (shift + bit)) & 1);
    }
  }

  for (let bit = 6; bit >= 0; bit -= 2) {
    for (let shift = 1; shift <= 25; shift += 8) {
      outputRight = (outputRight << 1) | ((inputRight >>> (shift + bit)) & 1);
    }
    for (let shift = 1; shift <= 25; shift += 8) {
      outputRight = (outputRight << 1) | ((inputLeft >>> (shift + bit)) & 1);
    }
  }

  output[offset] = outputLeft >>> 0;
  output[offset + 1] = outputRight >>> 0;
}

function reverseInitialPermutation(inputLeft: number, inputRight: number, output: number[], offset: number): void {
  let outputLeft = 0;
  let outputRight = 0;

  for (let bit = 0; bit < 4; bit++) {
    for (let shift = 24; shift >= 0; shift -= 8) {
      outputLeft = (outputLeft << 1) | ((inputRight >>> (shift + bit)) & 1);
      outputLeft = (outputLeft << 1) | ((inputLeft >>> (shift + bit)) & 1);
    }
  }

  for (let bit = 4; bit < 8; bit++) {
    for (let shift = 24; shift >= 0; shift -= 8) {
      outputRight = (outputRight << 1) | ((inputRight >>> (shift + bit)) & 1);
      outputRight = (outputRight << 1) | ((inputLeft >>> (shift + bit)) & 1);
    }
  }

  output[offset] = outputLeft >>> 0;
  output[offset + 1] = outputRight >>> 0;
}

function permutedChoice1(inputLeft: number, inputRight: number, output: number[], offset: number): void {
  let outputLeft = 0;
  let outputRight = 0;
  let bit = 0;

  for (bit = 7; bit >= 5; bit--) {
    for (let shift = 0; shift <= 24; shift += 8) {
      outputLeft = (outputLeft << 1) | ((inputRight >> (shift + bit)) & 1);
    }
    for (let shift = 0; shift <= 24; shift += 8) {
      outputLeft = (outputLeft << 1) | ((inputLeft >> (shift + bit)) & 1);
    }
  }
  for (let shift = 0; shift <= 24; shift += 8) {
    outputLeft = (outputLeft << 1) | ((inputRight >> (shift + bit)) & 1);
  }

  for (bit = 1; bit <= 3; bit++) {
    for (let shift = 0; shift <= 24; shift += 8) {
      outputRight = (outputRight << 1) | ((inputRight >> (shift + bit)) & 1);
    }
    for (let shift = 0; shift <= 24; shift += 8) {
      outputRight = (outputRight << 1) | ((inputLeft >> (shift + bit)) & 1);
    }
  }
  for (let shift = 0; shift <= 24; shift += 8) {
    outputRight = (outputRight << 1) | ((inputLeft >> (shift + bit)) & 1);
  }

  output[offset] = outputLeft >>> 0;
  output[offset + 1] = outputRight >>> 0;
}

function rotateLeft28(value: number, shift: number): number {
  return ((value << shift) & 0xfffffff) | (value >>> (28 - shift));
}

const PERMUTED_CHOICE2_TABLE = [
  14, 11, 17, 4, 27, 23, 25, 0,
  13, 22, 7, 18, 5, 9, 16, 24,
  2, 20, 12, 21, 1, 8, 15, 26,
  15, 4, 25, 19, 9, 1, 26, 16,
  5, 11, 23, 8, 12, 7, 17, 0,
  22, 3, 10, 14, 6, 20, 27, 24,
];

function permutedChoice2(inputLeft: number, inputRight: number, output: number[], offset: number): void {
  let outputLeft = 0;
  let outputRight = 0;
  const halfLength = PERMUTED_CHOICE2_TABLE.length >>> 1;

  for (let index = 0; index < halfLength; index++) {
    outputLeft = (outputLeft << 1) | ((inputLeft >>> PERMUTED_CHOICE2_TABLE[index]) & 1);
  }
  for (let index = halfLength; index < PERMUTED_CHOICE2_TABLE.length; index++) {
    outputRight = (outputRight << 1) | ((inputRight >>> PERMUTED_CHOICE2_TABLE[index]) & 1);
  }

  output[offset] = outputLeft >>> 0;
  output[offset + 1] = outputRight >>> 0;
}

function expand(right: number, output: number[], offset: number): void {
  let outputLeft = ((right & 1) << 5) | (right >>> 27);
  let outputRight = 0;

  for (let bit = 23; bit >= 15; bit -= 4) {
    outputLeft = (outputLeft << 6) | ((right >>> bit) & 0x3f);
  }
  for (let bit = 11; bit >= 3; bit -= 4) {
    outputRight |= (right >>> bit) & 0x3f;
    outputRight <<= 6;
  }
  outputRight |= ((right & 0x1f) << 1) | (right >>> 31);

  output[offset] = outputLeft >>> 0;
  output[offset + 1] = outputRight >>> 0;
}

function substitute(inputLeft: number, inputRight: number): number {
  let output = 0;
  for (let index = 0; index < 4; index++) {
    output = (output << 4) | S_TABLE[index * 0x40 + ((inputLeft >>> (18 - index * 6)) & 0x3f)];
  }
  for (let index = 0; index < 4; index++) {
    output = (output << 4) | S_TABLE[4 * 0x40 + index * 0x40 + ((inputRight >>> (18 - index * 6)) & 0x3f)];
  }
  return output >>> 0;
}

const PERMUTE_TABLE = [
  16, 25, 12, 11, 3, 20, 4, 15, 31, 17, 9, 6, 27, 14, 1, 22,
  30, 24, 8, 18, 0, 5, 29, 23, 13, 19, 2, 26, 10, 21, 28, 7,
];

function permute(value: number): number {
  let output = 0;
  for (const bit of PERMUTE_TABLE) {
    output = (output << 1) | ((value >>> bit) & 1);
  }
  return output >>> 0;
}

const KEY_SHIFTS = [
  1, 1, 2, 2, 2, 2, 2, 2,
  1, 2, 2, 2, 2, 2, 2, 1,
];

const S_TABLE = [
  14, 0, 4, 15, 13, 7, 1, 4, 2, 14, 15, 2, 11, 13, 8, 1,
  3, 10, 10, 6, 6, 12, 12, 11, 5, 9, 9, 5, 0, 3, 7, 8,
  4, 15, 1, 12, 14, 8, 8, 2, 13, 4, 6, 9, 2, 1, 11, 7,
  15, 5, 12, 11, 9, 3, 7, 14, 3, 10, 10, 0, 5, 6, 0, 13,
  15, 3, 1, 13, 8, 4, 14, 7, 6, 15, 11, 2, 3, 8, 4, 14,
  9, 12, 7, 0, 2, 1, 13, 10, 12, 6, 0, 9, 5, 11, 10, 5,
  0, 13, 14, 8, 7, 10, 11, 1, 10, 3, 4, 15, 13, 4, 1, 2,
  5, 11, 8, 6, 12, 7, 6, 12, 9, 0, 3, 5, 2, 14, 15, 9,
  10, 13, 0, 7, 9, 0, 14, 9, 6, 3, 3, 4, 15, 6, 5, 10,
  1, 2, 13, 8, 12, 5, 7, 14, 11, 12, 4, 11, 2, 15, 8, 1,
  13, 1, 6, 10, 4, 13, 9, 0, 8, 6, 15, 9, 3, 8, 0, 7,
  11, 4, 1, 15, 2, 14, 12, 3, 5, 11, 10, 5, 14, 2, 7, 12,
  7, 13, 13, 8, 14, 11, 3, 5, 0, 6, 6, 15, 9, 0, 10, 3,
  1, 4, 2, 7, 8, 2, 5, 12, 11, 1, 12, 10, 4, 14, 15, 9,
  10, 3, 6, 15, 9, 0, 0, 6, 12, 10, 11, 1, 7, 13, 13, 8,
  15, 9, 1, 4, 3, 5, 14, 11, 5, 12, 2, 7, 8, 2, 4, 14,
  2, 14, 12, 11, 4, 2, 1, 12, 7, 4, 10, 7, 11, 13, 6, 1,
  8, 5, 5, 0, 3, 15, 15, 10, 13, 3, 0, 9, 14, 8, 9, 6,
  4, 11, 2, 8, 1, 12, 11, 7, 10, 1, 13, 14, 7, 2, 8, 13,
  15, 6, 9, 15, 12, 0, 5, 9, 6, 10, 3, 4, 0, 5, 14, 3,
  12, 10, 1, 15, 10, 4, 15, 2, 9, 7, 2, 12, 6, 9, 8, 5,
  0, 6, 13, 1, 3, 13, 4, 14, 14, 0, 7, 11, 5, 3, 11, 8,
  9, 4, 14, 3, 15, 2, 5, 12, 2, 9, 8, 5, 12, 15, 3, 10,
  7, 11, 0, 14, 4, 1, 10, 7, 1, 6, 13, 0, 11, 8, 6, 13,
  4, 13, 11, 0, 2, 11, 14, 7, 15, 4, 0, 9, 8, 1, 13, 10,
  3, 14, 12, 3, 9, 5, 7, 12, 5, 2, 10, 15, 6, 8, 1, 6,
  1, 6, 4, 11, 11, 13, 13, 8, 12, 1, 3, 4, 7, 10, 14, 7,
  10, 9, 15, 5, 6, 0, 8, 15, 0, 14, 5, 2, 9, 3, 2, 12,
  13, 1, 2, 15, 8, 13, 4, 8, 6, 10, 15, 3, 11, 7, 1, 4,
  10, 12, 9, 5, 3, 6, 14, 11, 5, 0, 0, 14, 12, 9, 7, 2,
  7, 2, 11, 1, 4, 14, 1, 7, 9, 4, 12, 10, 14, 8, 2, 13,
  0, 15, 6, 12, 10, 9, 13, 0, 15, 3, 3, 5, 5, 6, 8, 11,
];

function assertBlocks(input: Uint8Array, output: Uint8Array, name: string): void {
  if (input.length % 8 !== 0) {
    throw new Error(`${name} input length must be a multiple of 64 bits.`);
  }
  if (output.length !== input.length) {
    throw new Error(`${name} output length must equal input length.`);
  }
}
