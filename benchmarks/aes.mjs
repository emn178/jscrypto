import assert from 'node:assert/strict';
import { createCipheriv, createDecipheriv } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { createAesCipher } from '@jscrypto/classic';
import { ecb as nobleEcb } from '@noble/ciphers/aes.js';
import CryptoJS from 'crypto-js';

const BLOCK_SIZE = 16;
const DEFAULT_BLOCKS = 200_000;
const DEFAULT_WARMUP_BLOCKS = 20_000;

const keyHexByBits = {
  128: '000102030405060708090a0b0c0d0e0f',
  192: '000102030405060708090a0b0c0d0e0f1011121314151617',
  256: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
};

const blockHex = '00112233445566778899aabbccddeeff';

const options = parseOptions(process.argv.slice(2));

console.log('AES raw-block throughput benchmark');
console.log('Scope: AES over raw 16-byte blocks. ECB/no padding is used only for APIs without raw block transforms.');
console.log(`Node: ${process.version}`);
console.log(`Blocks: ${options.blocks.toLocaleString()} (${formatBytes(options.blocks * BLOCK_SIZE)})`);
console.log(`Warmup blocks: ${options.warmupBlocks.toLocaleString()}`);
console.log('');

const rows = [];
// for (const bits of [128, 192, 256]) {
for (const bits of [256]) {
  rows.push(runSuite(bits, 'encrypt'));
  rows.push(runSuite(bits, 'decrypt'));
}

printTable(rows);

function runSuite(bits, direction) {
  const key = hexToBytes(keyHexByBits[bits]);
  const block = hexToBytes(blockHex);
  const plaintext = repeatBlock(block, options.blocks);
  const jscryptoCipher = createAesCipher(key);
  const cryptoJsKey = wordArrayFromBytes(key);
  const cryptoJsEncryptor = CryptoJS.algo.AES.createEncryptor(cryptoJsKey);
  const cryptoJsDecryptor = CryptoJS.algo.AES.createDecryptor(cryptoJsKey);

  const ciphertext = encryptJscryptoBlocks(jscryptoCipher, plaintext);
  const input = direction === 'encrypt' ? plaintext : ciphertext;

  assertMatchingOutput({
    bits,
    direction,
    jscryptoCipher,
    key,
    input,
    cryptoJsEncryptor,
    cryptoJsDecryptor,
  });

  const jscrypto = measure(`${bits} jscrypto ${direction}`, options.warmupBlocks, options.blocks, (blocks) => {
    const source = input.subarray(0, blocks * BLOCK_SIZE);
    const output = direction === 'encrypt'
      ? encryptJscryptoBlocks(jscryptoCipher, source)
      : decryptJscryptoBlocks(jscryptoCipher, source);
    return checksumBytes(output);
  });

  const jscryptoMutable = measure(`${bits} jscrypto mutable ${direction}`, options.warmupBlocks, options.blocks, (blocks) => {
    const source = input.slice(0, blocks * BLOCK_SIZE);
    const output = direction === 'encrypt'
      ? encryptJscryptoBlocks(jscryptoCipher, source, source)
      : decryptJscryptoBlocks(jscryptoCipher, source, source);
    return checksumBytes(output);
  });

  const cryptojs = measure(`${bits} crypto-js ${direction}`, options.warmupBlocks, options.blocks, (blocks) => {
    const words = wordsFromBytes(input.subarray(0, blocks * BLOCK_SIZE));
    const transform = direction === 'encrypt'
      ? cryptoJsEncryptor.encryptBlock.bind(cryptoJsEncryptor)
      : cryptoJsDecryptor.decryptBlock.bind(cryptoJsDecryptor);
    for (let index = 0; index < blocks; index++) {
      transform(words, index * 4);
    }
    return checksumWords(words, blocks * BLOCK_SIZE);
  });

  const noble = measure(`${bits} noble ${direction}`, options.warmupBlocks, options.blocks, (blocks) => {
    const source = input.subarray(0, blocks * BLOCK_SIZE);
    const cipher = nobleEcb(key, { disablePadding: true });
    const output = direction === 'encrypt' ? cipher.encrypt(source) : cipher.decrypt(source);
    return checksumBytes(output);
  });

  const node = measure(`${bits} node ${direction}`, options.warmupBlocks, options.blocks, (blocks) => {
    const source = input.subarray(0, blocks * BLOCK_SIZE);
    const output = direction === 'encrypt'
      ? runNodeAesEcb(bits, key, source, true)
      : runNodeAesEcb(bits, key, source, false);
    return checksumBytes(output);
  });

  return {
    aes: `AES-${bits}`,
    direction,
    jscrypto,
    jscryptoMutable,
    cryptojs,
    noble,
    node,
    ratio: jscrypto.opsPerSecond / cryptojs.opsPerSecond,
  };
}

function measure(name, warmupBlocks, blocks, fn) {
  fn(warmupBlocks);

  const start = performance.now();
  const checksum = fn(blocks);
  const milliseconds = performance.now() - start;
  const seconds = milliseconds / 1000;
  return {
    name,
    checksum,
    milliseconds,
    opsPerSecond: blocks / seconds,
    bytesPerSecond: (blocks * BLOCK_SIZE) / seconds,
  };
}

function assertMatchingOutput({
  bits,
  direction,
  jscryptoCipher,
  key,
  input,
  cryptoJsEncryptor,
  cryptoJsDecryptor,
}) {
  const jscryptoOutput = direction === 'encrypt'
    ? encryptJscryptoBlocks(jscryptoCipher, input)
    : decryptJscryptoBlocks(jscryptoCipher, input);
  const cryptoJsOutputWords = runCryptoJsBlocks(
    direction === 'encrypt' ? cryptoJsEncryptor : cryptoJsDecryptor,
    direction,
    wordsFromBytes(input),
    input.length / BLOCK_SIZE,
  );
  const nobleCipher = nobleEcb(key, { disablePadding: true });
  const nobleOutput = direction === 'encrypt' ? nobleCipher.encrypt(input) : nobleCipher.decrypt(input);
  const nodeOutput = runNodeAesEcb(bits, key, input, direction === 'encrypt');
  assert.deepEqual(
    Array.from(jscryptoOutput),
    Array.from(bytesFromWords(cryptoJsOutputWords, input.length)),
    `AES-${bits} ${direction} crypto-js output mismatch`,
  );
  assert.deepEqual(
    Array.from(jscryptoOutput),
    Array.from(nobleOutput),
    `AES-${bits} ${direction} noble output mismatch`,
  );
  assert.deepEqual(
    Array.from(jscryptoOutput),
    Array.from(nodeOutput),
    `AES-${bits} ${direction} node output mismatch`,
  );
}

function runCryptoJsBlocks(transformer, direction, inputWords, blocks) {
  const words = inputWords.slice();
  for (let index = 0; index < blocks; index++) {
    if (direction === 'encrypt') {
      transformer.encryptBlock(words, index * 4);
    } else {
      transformer.decryptBlock(words, index * 4);
    }
  }
  return words;
}

function encryptJscryptoBlocks(cipher, input, output) {
  return cipher.encrypt(input, output ?? new Uint8Array(input.length));
}

function decryptJscryptoBlocks(cipher, input, output) {
  return cipher.decrypt(input, output ?? new Uint8Array(input.length));
}

function runNodeAesEcb(bits, key, input, encrypt) {
  const transform = encrypt
    ? createCipheriv(`aes-${bits}-ecb`, key, null)
    : createDecipheriv(`aes-${bits}-ecb`, key, null);
  transform.setAutoPadding(false);
  return new Uint8Array(Buffer.concat([transform.update(input), transform.final()]));
}

function parseOptions(args) {
  const options = {
    blocks: DEFAULT_BLOCKS,
    warmupBlocks: DEFAULT_WARMUP_BLOCKS,
  };

  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (arg === '--blocks') {
      options.blocks = parsePositiveInteger(args[++index], 'blocks');
    } else if (arg.startsWith('--blocks=')) {
      options.blocks = parsePositiveInteger(arg.slice('--blocks='.length), 'blocks');
    } else if (arg === '--warmup-blocks') {
      options.warmupBlocks = parsePositiveInteger(args[++index], 'warmup-blocks');
    } else if (arg.startsWith('--warmup-blocks=')) {
      options.warmupBlocks = parsePositiveInteger(arg.slice('--warmup-blocks='.length), 'warmup-blocks');
    } else if (arg === '--help' || arg === '-h') {
      printHelp();
      process.exit(0);
    } else {
      throw new Error(`Unknown option: ${arg}`);
    }
  }

  return options;
}

function parsePositiveInteger(value, label) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number <= 0) {
    throw new Error(`${label} must be a positive integer.`);
  }
  return number;
}

function printHelp() {
  console.log(`Usage: npm run benchmark:aes -- [options]

Options:
  --blocks <n>          Number of measured AES blocks. Default: ${DEFAULT_BLOCKS}
  --warmup-blocks <n>   Number of warmup AES blocks per case. Default: ${DEFAULT_WARMUP_BLOCKS}
`);
}

function printTable(rows) {
  for (const row of rows) {
    console.log(`${row.aes} ${row.direction}`);
    // console.log(`  jscrypto          ${formatNumber(row.jscrypto.opsPerSecond).padStart(12)} ops/s  ${formatNumber(row.jscrypto.bytesPerSecond / 1024 / 1024).padStart(5)} MiB/s`);
    console.log(`  jscrypto mutable  ${formatNumber(row.jscryptoMutable.opsPerSecond).padStart(12)} ops/s  ${formatNumber(row.jscryptoMutable.bytesPerSecond / 1024 / 1024).padStart(5)} MiB/s`);
    // console.log(`  crypto-js         ${formatNumber(row.cryptojs.opsPerSecond).padStart(12)} ops/s  ${formatNumber(row.cryptojs.bytesPerSecond / 1024 / 1024).padStart(5)} MiB/s`);
    console.log(`  noble             ${formatNumber(row.noble.opsPerSecond).padStart(12)} ops/s  ${formatNumber(row.noble.bytesPerSecond / 1024 / 1024).padStart(5)} MiB/s`);
    // console.log(`  node              ${formatNumber(row.node.opsPerSecond).padStart(12)} ops/s  ${formatNumber(row.node.bytesPerSecond / 1024 / 1024).padStart(5)} MiB/s`);
    // console.log(`  jscrypto/crypto-js ${row.ratio.toFixed(2)}x`);
    console.log('');
  }

  const checksum = rows.reduce(
    (acc, row) => (
      acc + row.jscrypto.checksum + row.cryptojs.checksum + row.noble.checksum + row.node.checksum
      + row.jscryptoMutable.checksum
    ) >>> 0,
    0,
  );
  console.log(`Checksum: ${checksum}`);
}

function formatNumber(value) {
  return Math.round(value).toLocaleString();
}

function formatBytes(bytes) {
  return `${(bytes / 1024 / 1024).toFixed(2)} MiB`;
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index++) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function wordArrayFromBytes(bytes) {
  return CryptoJS.lib.WordArray.create(wordsFromBytes(bytes), bytes.length);
}

function wordsFromBytes(bytes) {
  const words = [];
  for (let index = 0; index < bytes.length; index++) {
    words[index >>> 2] |= bytes[index] << (24 - (index % 4) * 8);
  }
  return words;
}

function bytesFromWords(words, length) {
  const bytes = new Uint8Array(length);
  for (let index = 0; index < bytes.length; index++) {
    bytes[index] = (words[index >>> 2] >>> (24 - (index % 4) * 8)) & 0xff;
  }
  return bytes;
}

function repeatBlock(block, blocks) {
  const bytes = new Uint8Array(block.length * blocks);
  for (let offset = 0; offset < bytes.length; offset += block.length) {
    bytes.set(block, offset);
  }
  return bytes;
}

function checksumBytes(bytes) {
  let checksum = 0;
  for (let index = 0; index < bytes.length; index++) {
    checksum = (checksum + bytes[index]) >>> 0;
  }
  return checksum;
}

function checksumWords(words, length) {
  let checksum = 0;
  for (let index = 0; index < length; index++) {
    checksum = (checksum + ((words[index >>> 2] >>> (24 - (index % 4) * 8)) & 0xff)) >>> 0;
  }
  return checksum;
}
