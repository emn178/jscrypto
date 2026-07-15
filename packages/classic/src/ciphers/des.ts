import type { BlockCipher, CipherComponent } from '@jscrypto/core';
import {
  expansionPermutation,
  finalPermutation,
  initialPermutation,
  keyPermutation,
  keyShifts,
  roundPermutation,
  subkeyPermutation,
  substitutionBoxes,
} from './des-tables.js';

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

  return {
    blockSize: 8,

    encryptBlock(block) {
      assertBlock(block, 'DES');
      return processBlock(block, subkeys);
    },

    decryptBlock(block) {
      assertBlock(block, 'DES');
      return processBlock(block, subkeys.slice().reverse());
    },
  };
}

function createSubkeys(key: Uint8Array): Uint8Array[] {
  const keyBits = permute(bytesToBits(key), keyPermutation);
  const left = keyBits.slice(0, 28);
  const right = keyBits.slice(28);
  const subkeys: Uint8Array[] = [];

  for (const shift of keyShifts) {
    rotateLeft(left, shift);
    rotateLeft(right, shift);
    subkeys.push(permute(joinBits(left, right), subkeyPermutation));
  }

  return subkeys;
}

function processBlock(block: Uint8Array, subkeys: readonly Uint8Array[]): Uint8Array {
  const bits = permute(bytesToBits(block), initialPermutation);
  let left = bits.slice(0, 32);
  let right = bits.slice(32);

  for (const subkey of subkeys) {
    const nextLeft = right;
    const nextRight = xorBits(left, feistel(right, subkey));
    left = nextLeft;
    right = nextRight;
  }

  return bitsToBytes(permute(joinBits(right, left), finalPermutation));
}

function feistel(input: Uint8Array, subkey: Uint8Array): Uint8Array {
  const expanded = xorBits(permute(input, expansionPermutation), subkey);
  const substituted = new Uint8Array(32);

  for (let box = 0; box < substitutionBoxes.length; box++) {
    const offset = box * 6;
    const row = (expanded[offset] << 1) | expanded[offset + 5];
    const column = (expanded[offset + 1] << 3)
      | (expanded[offset + 2] << 2)
      | (expanded[offset + 3] << 1)
      | expanded[offset + 4];
    const value = substitutionBoxes[box][row * 16 + column];

    for (let bit = 0; bit < 4; bit++) {
      substituted[box * 4 + bit] = (value >>> (3 - bit)) & 1;
    }
  }

  return permute(substituted, roundPermutation);
}

function bytesToBits(bytes: Uint8Array): Uint8Array {
  const bits = new Uint8Array(bytes.length * 8);

  for (let i = 0; i < bits.length; i++) {
    bits[i] = (bytes[i >>> 3] >>> (7 - (i & 7))) & 1;
  }

  return bits;
}

function bitsToBytes(bits: Uint8Array): Uint8Array {
  const bytes = new Uint8Array(bits.length / 8);

  for (let i = 0; i < bits.length; i++) {
    bytes[i >>> 3] |= bits[i] << (7 - (i & 7));
  }

  return bytes;
}

function permute(bits: Uint8Array, table: readonly number[]): Uint8Array {
  const output = new Uint8Array(table.length);

  for (let i = 0; i < table.length; i++) {
    output[i] = bits[table[i] - 1];
  }

  return output;
}

function rotateLeft(bits: Uint8Array, count: number): void {
  const first = bits.slice(0, count);
  bits.copyWithin(0, count);
  bits.set(first, bits.length - count);
}

function joinBits(left: Uint8Array, right: Uint8Array): Uint8Array {
  const output = new Uint8Array(left.length + right.length);
  output.set(left);
  output.set(right, left.length);
  return output;
}

function xorBits(left: Uint8Array, right: Uint8Array): Uint8Array {
  const output = new Uint8Array(left.length);

  for (let i = 0; i < output.length; i++) {
    output[i] = left[i] ^ right[i];
  }

  return output;
}

function assertBlock(block: Uint8Array, name: string): void {
  if (block.length !== 8) {
    throw new Error(`${name} block must be 64 bits.`);
  }
}
