function rotl(value: number, amount: number): number {
  return (value << amount) | (value >>> (32 - amount));
}

function rotr(value: number, amount: number): number {
  return (value >>> amount) | (value << (32 - amount));
}

function padded(input: Uint8Array, blockSize: number, littleEndianLength = false): Uint8Array {
  const lengthBytes = blockSize === 128 ? 16 : 8;
  const total = Math.ceil((input.length + 1 + lengthBytes) / blockSize) * blockSize;
  const output = new Uint8Array(total);
  output.set(input);
  output[input.length] = 0x80;
  const bitLength = input.length * 8;
  const lengthOffset = total - 8;

  for (let i = 0; i < 8; i++) {
    const shift = littleEndianLength ? i * 8 : (7 - i) * 8;
    output[lengthOffset + i] = Math.floor(bitLength / 2 ** shift) & 0xff;
  }
  return output;
}

function write32(output: Uint8Array, offset: number, value: number, littleEndian = false): void {
  if (littleEndian) {
    output[offset] = value & 0xff;
    output[offset + 1] = (value >>> 8) & 0xff;
    output[offset + 2] = (value >>> 16) & 0xff;
    output[offset + 3] = value >>> 24;
    return;
  }
  output[offset] = value >>> 24;
  output[offset + 1] = (value >>> 16) & 0xff;
  output[offset + 2] = (value >>> 8) & 0xff;
  output[offset + 3] = value & 0xff;
}

function read32(input: Uint8Array, offset: number, littleEndian = false): number {
  if (littleEndian) {
    return input[offset] | (input[offset + 1] << 8) | (input[offset + 2] << 16) | (input[offset + 3] << 24);
  }
  return (input[offset] << 24) | (input[offset + 1] << 16) | (input[offset + 2] << 8) | input[offset + 3];
}

export function md5Hash(input: Uint8Array): Uint8Array {
  const data = padded(input, 64, true);
  let a0 = 0x67452301;
  let b0 = 0xefcdab89;
  let c0 = 0x98badcfe;
  let d0 = 0x10325476;
  const shifts = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
  ];
  const constants = Array.from({ length: 64 }, (_, index) => Math.floor(Math.abs(Math.sin(index + 1)) * 0x100000000) | 0);

  for (let offset = 0; offset < data.length; offset += 64) {
    const words = Array.from({ length: 16 }, (_, index) => read32(data, offset + index * 4, true));
    let a = a0;
    let b = b0;
    let c = c0;
    let d = d0;
    for (let i = 0; i < 64; i++) {
      let f: number;
      let g: number;
      if (i < 16) {
        f = (b & c) | (~b & d);
        g = i;
      } else if (i < 32) {
        f = (d & b) | (~d & c);
        g = (5 * i + 1) % 16;
      } else if (i < 48) {
        f = b ^ c ^ d;
        g = (3 * i + 5) % 16;
      } else {
        f = c ^ (b | ~d);
        g = (7 * i) % 16;
      }
      const next = d;
      d = c;
      c = b;
      b = (b + rotl((a + f + constants[i] + words[g]) | 0, shifts[i])) | 0;
      a = next;
    }
    a0 = (a0 + a) | 0;
    b0 = (b0 + b) | 0;
    c0 = (c0 + c) | 0;
    d0 = (d0 + d) | 0;
  }
  const output = new Uint8Array(16);
  [a0, b0, c0, d0].forEach((value, index) => write32(output, index * 4, value, true));
  return output;
}

export function sha1Hash(input: Uint8Array): Uint8Array {
  const data = padded(input, 64);
  let h0 = 0x67452301;
  let h1 = 0xefcdab89;
  let h2 = 0x98badcfe;
  let h3 = 0x10325476;
  let h4 = 0xc3d2e1f0;
  for (let offset = 0; offset < data.length; offset += 64) {
    const words = new Int32Array(80);
    for (let i = 0; i < 16; i++) words[i] = read32(data, offset + i * 4);
    for (let i = 16; i < 80; i++) words[i] = rotl(words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16], 1);
    let a = h0; let b = h1; let c = h2; let d = h3; let e = h4;
    for (let i = 0; i < 80; i++) {
      const f = i < 20 ? ((b & c) | (~b & d)) : i < 40 ? (b ^ c ^ d) : i < 60 ? ((b & c) | (b & d) | (c & d)) : (b ^ c ^ d);
      const k = i < 20 ? 0x5a827999 : i < 40 ? 0x6ed9eba1 : i < 60 ? 0x8f1bbcdc : 0xca62c1d6;
      const next = (rotl(a, 5) + f + e + k + words[i]) | 0;
      e = d; d = c; c = rotl(b, 30); b = a; a = next;
    }
    h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0; h4 = (h4 + e) | 0;
  }
  const output = new Uint8Array(20);
  [h0, h1, h2, h3, h4].forEach((value, index) => write32(output, index * 4, value));
  return output;
}

const SHA256_CONSTANTS = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

function sha256(input: Uint8Array, state: number[]): Uint8Array {
  const data = padded(input, 64);
  for (let offset = 0; offset < data.length; offset += 64) {
    const words = new Int32Array(64);
    for (let i = 0; i < 16; i++) words[i] = read32(data, offset + i * 4);
    for (let i = 16; i < 64; i++) {
      const a = words[i - 15]; const b = words[i - 2];
      words[i] = (rotr(a, 7) ^ rotr(a, 18) ^ (a >>> 3)) + words[i - 16] + (rotr(b, 17) ^ rotr(b, 19) ^ (b >>> 10)) + words[i - 7];
    }
    let [a, b, c, d, e, f, g, h] = state;
    for (let i = 0; i < 64; i++) {
      const s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const choice = (e & f) ^ (~e & g);
      const t1 = (h + s1 + choice + SHA256_CONSTANTS[i] + words[i]) | 0;
      const s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const majority = (a & b) ^ (a & c) ^ (b & c);
      h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + s0 + majority) | 0;
    }
    state[0] = (state[0] + a) | 0; state[1] = (state[1] + b) | 0; state[2] = (state[2] + c) | 0; state[3] = (state[3] + d) | 0;
    state[4] = (state[4] + e) | 0; state[5] = (state[5] + f) | 0; state[6] = (state[6] + g) | 0; state[7] = (state[7] + h) | 0;
  }
  const output = new Uint8Array(state.length * 4);
  state.forEach((value, index) => write32(output, index * 4, value));
  return output;
}

export function sha224Hash(input: Uint8Array): Uint8Array {
  return sha256(input, [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4]).slice(0, 28);
}

export function sha256Hash(input: Uint8Array): Uint8Array {
  return sha256(input, [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
}

const RIPEMD_LEFT = [
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
  3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
  4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
];
const RIPEMD_RIGHT = [
  5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
  15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
  12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
];
const RIPEMD_LEFT_ROTATIONS = [
  11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
  11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
  9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
];
const RIPEMD_RIGHT_ROTATIONS = [
  8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
  9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
  8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
];

function ripemdFunction(round: number, x: number, y: number, z: number): number {
  if (round === 0) return x ^ y ^ z;
  if (round === 1) return (x & y) | (~x & z);
  if (round === 2) return (x | ~y) ^ z;
  if (round === 3) return (x & z) | (y & ~z);
  return x ^ (y | ~z);
}

export function ripemd160Hash(input: Uint8Array): Uint8Array {
  const data = padded(input, 64, true);
  let h0 = 0x67452301; let h1 = 0xefcdab89; let h2 = 0x98badcfe; let h3 = 0x10325476; let h4 = 0xc3d2e1f0;
  const leftConstants = [0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e];
  const rightConstants = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000];
  for (let offset = 0; offset < data.length; offset += 64) {
    const words = Array.from({ length: 16 }, (_, index) => read32(data, offset + index * 4, true));
    let al = h0; let bl = h1; let cl = h2; let dl = h3; let el = h4;
    let ar = h0; let br = h1; let cr = h2; let dr = h3; let er = h4;
    for (let i = 0; i < 80; i++) {
      const round = i >>> 4;
      const left = (rotl((al + ripemdFunction(round, bl, cl, dl) + words[RIPEMD_LEFT[i]] + leftConstants[round]) | 0, RIPEMD_LEFT_ROTATIONS[i]) + el) | 0;
      al = el; el = dl; dl = rotl(cl, 10); cl = bl; bl = left;
      const rightRound = 4 - round;
      const right = (rotl((ar + ripemdFunction(rightRound, br, cr, dr) + words[RIPEMD_RIGHT[i]] + rightConstants[round]) | 0, RIPEMD_RIGHT_ROTATIONS[i]) + er) | 0;
      ar = er; er = dr; dr = rotl(cr, 10); cr = br; br = right;
    }
    const next = (h1 + cl + dr) | 0;
    h1 = (h2 + dl + er) | 0; h2 = (h3 + el + ar) | 0; h3 = (h4 + al + br) | 0; h4 = (h0 + bl + cr) | 0; h0 = next;
  }
  const output = new Uint8Array(20);
  [h0, h1, h2, h3, h4].forEach((value, index) => write32(output, index * 4, value, true));
  return output;
}

type Word64 = [number, number];

function add64(...words: number[]): Word64 {
  let high = 0;
  let low = 0;
  for (let i = 0; i < words.length; i += 2) {
    const next = low + (words[i + 1] >>> 0);
    high += (words[i] >>> 0) + (next >= 0x100000000 ? 1 : 0);
    low = next >>> 0;
  }
  return [high >>> 0, low];
}

function rotate64(high: number, low: number, amount: number): Word64 {
  if (amount < 32) return [(high >>> amount) | (low << (32 - amount)), (low >>> amount) | (high << (32 - amount))];
  amount -= 32;
  return [(low >>> amount) | (high << (32 - amount)), (high >>> amount) | (low << (32 - amount))];
}

function shift64(high: number, low: number, amount: number): Word64 {
  return [high >>> amount, (low >>> amount) | (high << (32 - amount))];
}

const SHA512_CONSTANTS = [
  '428a2f98d728ae22', '7137449123ef65cd', 'b5c0fbcfec4d3b2f', 'e9b5dba58189dbbc', '3956c25bf348b538', '59f111f1b605d019', '923f82a4af194f9b', 'ab1c5ed5da6d8118',
  'd807aa98a3030242', '12835b0145706fbe', '243185be4ee4b28c', '550c7dc3d5ffb4e2', '72be5d74f27b896f', '80deb1fe3b1696b1', '9bdc06a725c71235', 'c19bf174cf692694',
  'e49b69c19ef14ad2', 'efbe4786384f25e3', '0fc19dc68b8cd5b5', '240ca1cc77ac9c65', '2de92c6f592b0275', '4a7484aa6ea6e483', '5cb0a9dcbd41fbd4', '76f988da831153b5',
  '983e5152ee66dfab', 'a831c66d2db43210', 'b00327c898fb213f', 'bf597fc7beef0ee4', 'c6e00bf33da88fc2', 'd5a79147930aa725', '06ca6351e003826f', '142929670a0e6e70',
  '27b70a8546d22ffc', '2e1b21385c26c926', '4d2c6dfc5ac42aed', '53380d139d95b3df', '650a73548baf63de', '766a0abb3c77b2a8', '81c2c92e47edaee6', '92722c851482353b',
  'a2bfe8a14cf10364', 'a81a664bbc423001', 'c24b8b70d0f89791', 'c76c51a30654be30', 'd192e819d6ef5218', 'd69906245565a910', 'f40e35855771202a', '106aa07032bbd1b8',
  '19a4c116b8d2d0c8', '1e376c085141ab53', '2748774cdf8eeb99', '34b0bcb5e19b48a8', '391c0cb3c5c95a63', '4ed8aa4ae3418acb', '5b9cca4f7763e373', '682e6ff3d6b2b8a3',
  '748f82ee5defb2fc', '78a5636f43172f60', '84c87814a1f0ab72', '8cc702081a6439ec', '90befffa23631e28', 'a4506cebde82bde9', 'bef9a3f7b2c67915', 'c67178f2e372532b',
  'ca273eceea26619c', 'd186b8c721c0c207', 'eada7dd6cde0eb1e', 'f57d4f7fee6ed178', '06f067aa72176fba', '0a637dc5a2c898a6', '113f9804bef90dae', '1b710b35131c471b',
  '28db77f523047d84', '32caab7b40c72493', '3c9ebe0a15c9bebc', '431d67c49c100d4c', '4cc5d4becb3e42b6', '597f299cfc657e2a', '5fcb6fab3ad6faec', '6c44198c4a475817',
].map((value): Word64 => [Number.parseInt(value.slice(0, 8), 16), Number.parseInt(value.slice(8), 16)]);

function sha512(input: Uint8Array, state: number[]): Uint8Array {
  const data = padded(input, 128);
  for (let offset = 0; offset < data.length; offset += 128) {
    const words: Word64[] = Array.from({ length: 80 }, () => [0, 0]);
    for (let i = 0; i < 16; i++) words[i] = [read32(data, offset + i * 8), read32(data, offset + i * 8 + 4)];
    for (let i = 16; i < 80; i++) {
      const [aHigh, aLow] = words[i - 15];
      const [bHigh, bLow] = words[i - 2];
      const [a0High, a0Low] = rotate64(aHigh, aLow, 1);
      const [a1High, a1Low] = rotate64(aHigh, aLow, 8);
      const [a2High, a2Low] = shift64(aHigh, aLow, 7);
      const [b0High, b0Low] = rotate64(bHigh, bLow, 19);
      const [b1High, b1Low] = rotate64(bHigh, bLow, 61);
      const [b2High, b2Low] = shift64(bHigh, bLow, 6);
      words[i] = add64(...words[i - 16], a0High ^ a1High ^ a2High, a0Low ^ a1Low ^ a2Low, ...words[i - 7], b0High ^ b1High ^ b2High, b0Low ^ b1Low ^ b2Low);
    }
    let [aHigh, aLow, bHigh, bLow, cHigh, cLow, dHigh, dLow, eHigh, eLow, fHigh, fLow, gHigh, gLow, hHigh, hLow] = state;
    for (let i = 0; i < 80; i++) {
      const [e0High, e0Low] = rotate64(eHigh, eLow, 14);
      const [e1High, e1Low] = rotate64(eHigh, eLow, 18);
      const [e2High, e2Low] = rotate64(eHigh, eLow, 41);
      const [a0High, a0Low] = rotate64(aHigh, aLow, 28);
      const [a1High, a1Low] = rotate64(aHigh, aLow, 34);
      const [a2High, a2Low] = rotate64(aHigh, aLow, 39);
      const chooseHigh = (eHigh & fHigh) ^ (~eHigh & gHigh);
      const chooseLow = (eLow & fLow) ^ (~eLow & gLow);
      const majorityHigh = (aHigh & bHigh) ^ (aHigh & cHigh) ^ (bHigh & cHigh);
      const majorityLow = (aLow & bLow) ^ (aLow & cLow) ^ (bLow & cLow);
      const [t1High, t1Low] = add64(hHigh, hLow, e0High ^ e1High ^ e2High, e0Low ^ e1Low ^ e2Low, chooseHigh, chooseLow, ...SHA512_CONSTANTS[i], ...words[i]);
      const [t2High, t2Low] = add64(a0High ^ a1High ^ a2High, a0Low ^ a1Low ^ a2Low, majorityHigh, majorityLow);
      hHigh = gHigh; hLow = gLow; gHigh = fHigh; gLow = fLow; fHigh = eHigh; fLow = eLow;
      [eHigh, eLow] = add64(dHigh, dLow, t1High, t1Low);
      dHigh = cHigh; dLow = cLow; cHigh = bHigh; cLow = bLow; bHigh = aHigh; bLow = aLow;
      [aHigh, aLow] = add64(t1High, t1Low, t2High, t2Low);
    }
    const values = [aHigh, aLow, bHigh, bLow, cHigh, cLow, dHigh, dLow, eHigh, eLow, fHigh, fLow, gHigh, gLow, hHigh, hLow];
    for (let i = 0; i < values.length; i += 2) {
      const [nextHigh, nextLow] = add64(state[i], state[i + 1], values[i], values[i + 1]);
      state[i] = nextHigh;
      state[i + 1] = nextLow;
    }
  }
  const output = new Uint8Array(state.length * 4);
  state.forEach((value, index) => write32(output, index * 4, value));
  return output;
}

export function sha384Hash(input: Uint8Array): Uint8Array {
  return sha512(input, [
    0xcbbb9d5d, 0xc1059ed8, 0x629a292a, 0x367cd507, 0x9159015a, 0x3070dd17, 0x152fecd8, 0xf70e5939,
    0x67332667, 0xffc00b31, 0x8eb44a87, 0x68581511, 0xdb0c2e0d, 0x64f98fa7, 0x47b5481d, 0xbefa4fa4,
  ]).slice(0, 48);
}

export function sha512Hash(input: Uint8Array): Uint8Array {
  return sha512(input, [
    0x6a09e667, 0xf3bcc908, 0xbb67ae85, 0x84caa73b, 0x3c6ef372, 0xfe94f82b, 0xa54ff53a, 0x5f1d36f1,
    0x510e527f, 0xade682d1, 0x9b05688c, 0x2b3e6c1f, 0x1f83d9ab, 0xfb41bd6b, 0x5be0cd19, 0x137e2179,
  ]);
}

const KECCAK_ROTATIONS = [
  0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];
const KECCAK_ROUND_CONSTANTS: Word64[] = [
  [0, 1], [0, 0x8082], [0x80000000, 0x808a], [0x80000000, 0x80008000], [0, 0x808b], [0, 0x80000001],
  [0x80000000, 0x80008081], [0x80000000, 0x8009], [0, 0x8a], [0, 0x88], [0, 0x80008009], [0, 0x8000000a],
  [0, 0x8000808b], [0x80000000, 0x8b], [0x80000000, 0x8089], [0x80000000, 0x8003], [0x80000000, 0x8002], [0x80000000, 0x80],
  [0, 0x800a], [0x80000000, 0x8000000a], [0x80000000, 0x80008081], [0x80000000, 0x8080], [0, 0x80000001],
  [0x80000000, 0x80008008],
];

function rotateKeccak(lane: Uint8Array, amount: number): Uint8Array {
  const output = new Uint8Array(8);
  for (let bit = 0; bit < 64; bit++) {
    const source = (bit - amount + 64) % 64;
    output[bit >>> 3] |= ((lane[source >>> 3] >>> (source & 7)) & 1) << (bit & 7);
  }
  return output;
}

function keccakPermute(state: Uint8Array[]): void {
  for (const [roundHigh, roundLow] of KECCAK_ROUND_CONSTANTS) {
    const columns = Array.from({ length: 5 }, () => new Uint8Array(8));
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        for (let byte = 0; byte < 8; byte++) columns[x][byte] ^= state[x + 5 * y][byte];
      }
    }
    for (let x = 0; x < 5; x++) {
      const rotated = rotateKeccak(columns[(x + 1) % 5], 1);
      for (let y = 0; y < 5; y++) {
        const lane = state[x + 5 * y];
        for (let byte = 0; byte < 8; byte++) lane[byte] ^= columns[(x + 4) % 5][byte] ^ rotated[byte];
      }
    }
    const rotated = Array.from({ length: 25 }, () => new Uint8Array(8));
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) {
      rotated[y + 5 * ((2 * x + 3 * y) % 5)] = rotateKeccak(state[x + 5 * y], KECCAK_ROTATIONS[x + 5 * y]);
    }
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) {
      const lane = state[x + 5 * y];
      const current = rotated[x + 5 * y];
      const next = rotated[(x + 1) % 5 + 5 * y];
      const nextNext = rotated[(x + 2) % 5 + 5 * y];
      for (let byte = 0; byte < 8; byte++) lane[byte] = current[byte] ^ (~next[byte] & nextNext[byte]);
    }
    for (let byte = 0; byte < 4; byte++) {
      state[0][byte] ^= roundLow >>> (byte * 8);
      state[0][byte + 4] ^= roundHigh >>> (byte * 8);
    }
  }
}

export function sha3Hash(input: Uint8Array): Uint8Array {
  const rate = 72;
  const total = Math.ceil((input.length + 1) / rate) * rate;
  const data = new Uint8Array(total);
  data.set(input);
  data[input.length] = 0x01;
  data[total - 1] |= 0x80;
  const state = Array.from({ length: 25 }, () => new Uint8Array(8));
  for (let offset = 0; offset < data.length; offset += rate) {
    for (let lane = 0; lane < rate / 8; lane++) {
      const base = offset + lane * 8;
      for (let byte = 0; byte < 8; byte++) state[lane][byte] ^= data[base + byte];
    }
    keccakPermute(state);
  }
  const output = new Uint8Array(64);
  for (let lane = 0; lane < 8; lane++) output.set(state[lane], lane * 8);
  return output;
}
