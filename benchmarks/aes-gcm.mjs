import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { gcm as nobleGcm } from '@noble/ciphers/aes.js';
import { registry } from '../packages/classic/dist/index.mjs';

const DEFAULT_BYTES = 3_200_000;
const DEFAULT_WARMUP_BYTES = 320_000;
const DEFAULT_AAD_BYTES = 32;

const key = hexToBytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
const nonce = hexToBytes('101112131415161718191a1b');
const aadSeed = hexToBytes('feedfacedeadbeeffeedfacedeadbeefabaddad2');

const options = parseOptions(process.argv.slice(2));
const plaintext = repeatBytes(hexToBytes('00112233445566778899aabbccddeeff'), options.bytes);
const aad = repeatBytes(aadSeed, options.aadBytes);

console.log('AES-GCM throughput benchmark');
console.log('Scope: one-shot AES-256-GCM. jscrypto imports the browser/default build so AES blocks use @noble/ciphers, not Node native crypto.');
console.log(`Node: ${process.version}`);
console.log(`Plaintext: ${formatBytes(options.bytes)}`);
console.log(`AAD: ${formatBytes(options.aadBytes)}`);
console.log(`Warmup plaintext: ${formatBytes(options.warmupBytes)}`);
console.log('');

const jscryptoSealed = encryptJscrypto(plaintext);
const nobleSealed = encryptNoble(plaintext);
assert.deepEqual(Array.from(jscryptoSealed), Array.from(nobleSealed), 'jscrypto and noble AES-GCM ciphertext/tag mismatch');
assert.deepEqual(Array.from(decryptJscrypto(jscryptoSealed)), Array.from(plaintext), 'jscrypto AES-GCM decrypt mismatch');
assert.deepEqual(Array.from(decryptNoble(nobleSealed)), Array.from(plaintext), 'noble AES-GCM decrypt mismatch');

const rows = [
  runSuite('encrypt'),
  runSuite('decrypt'),
];

printTable(rows);

function runSuite(direction) {
  const measuredInput = direction === 'encrypt' ? plaintext : jscryptoSealed;
  const warmupPlaintext = plaintext.subarray(0, options.warmupBytes);
  const warmupInput = direction === 'encrypt' ? warmupPlaintext : encryptJscrypto(warmupPlaintext);

  const jscrypto = measure({
    measuredBytes: options.bytes,
    warmupInput,
    measuredInput,
    fn(source) {
      const output = direction === 'encrypt' ? encryptJscrypto(source) : decryptJscrypto(source);
      return checksumBytes(output);
    },
  });

  const noble = measure({
    measuredBytes: options.bytes,
    warmupInput,
    measuredInput,
    fn(source) {
      const output = direction === 'encrypt' ? encryptNoble(source) : decryptNoble(source);
      return checksumBytes(output);
    },
  });

  return {
    direction,
    jscrypto,
    noble,
    ratio: jscrypto.bytesPerSecond / noble.bytesPerSecond,
  };
}

function measure({ measuredBytes, warmupInput, measuredInput, fn }) {
  fn(warmupInput);

  const start = performance.now();
  const checksum = fn(measuredInput);
  const milliseconds = performance.now() - start;
  const seconds = milliseconds / 1000;
  return {
    checksum,
    milliseconds,
    bytesPerSecond: measuredBytes / seconds,
  };
}

function encryptJscrypto(input) {
  return registry.encrypt({
    cipher: 'AES',
    mode: 'GCM',
    key,
    nonce,
    aad,
    plaintext: input,
  });
}

function decryptJscrypto(input) {
  return registry.decrypt({
    cipher: 'AES',
    mode: 'GCM',
    key,
    nonce,
    aad,
    ciphertext: input,
  });
}

function encryptNoble(input) {
  return nobleGcm(key, nonce, aad).encrypt(input);
}

function decryptNoble(input) {
  return nobleGcm(key, nonce, aad).decrypt(input);
}

function parseOptions(args) {
  const options = {
    bytes: DEFAULT_BYTES,
    warmupBytes: DEFAULT_WARMUP_BYTES,
    aadBytes: DEFAULT_AAD_BYTES,
  };

  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (arg === '--bytes') {
      options.bytes = parsePositiveInteger(args[++index], 'bytes');
    } else if (arg.startsWith('--bytes=')) {
      options.bytes = parsePositiveInteger(arg.slice('--bytes='.length), 'bytes');
    } else if (arg === '--warmup-bytes') {
      options.warmupBytes = parsePositiveInteger(args[++index], 'warmup-bytes');
    } else if (arg.startsWith('--warmup-bytes=')) {
      options.warmupBytes = parsePositiveInteger(arg.slice('--warmup-bytes='.length), 'warmup-bytes');
    } else if (arg === '--aad-bytes') {
      options.aadBytes = parseNonNegativeInteger(args[++index], 'aad-bytes');
    } else if (arg.startsWith('--aad-bytes=')) {
      options.aadBytes = parseNonNegativeInteger(arg.slice('--aad-bytes='.length), 'aad-bytes');
    } else if (arg === '--help' || arg === '-h') {
      printHelp();
      process.exit(0);
    } else {
      throw new Error(`Unknown option: ${arg}`);
    }
  }

  if (options.warmupBytes > options.bytes) {
    throw new Error('warmup-bytes must be less than or equal to bytes.');
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

function parseNonNegativeInteger(value, label) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 0) {
    throw new Error(`${label} must be a non-negative integer.`);
  }
  return number;
}

function printHelp() {
  console.log(`Usage: npm run benchmark:aes-gcm -- [options]

Options:
  --bytes <n>          Number of measured plaintext bytes. Default: ${DEFAULT_BYTES}
  --warmup-bytes <n>   Number of warmup plaintext bytes per case. Default: ${DEFAULT_WARMUP_BYTES}
  --aad-bytes <n>      Number of AAD bytes. Default: ${DEFAULT_AAD_BYTES}
`);
}

function printTable(rows) {
  for (const row of rows) {
    console.log(`AES-256-GCM ${row.direction}`);
    console.log(`  jscrypto  ${formatNumber(row.jscrypto.bytesPerSecond / 1024 / 1024).padStart(6)} MiB/s`);
    console.log(`  noble     ${formatNumber(row.noble.bytesPerSecond / 1024 / 1024).padStart(6)} MiB/s`);
    console.log(`  ratio     ${row.ratio.toFixed(2)}x`);
    console.log('');
  }

  const checksum = rows.reduce(
    (acc, row) => (acc + row.jscrypto.checksum + row.noble.checksum) >>> 0,
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

function repeatBytes(seed, length) {
  const bytes = new Uint8Array(length);
  for (let offset = 0; offset < bytes.length; offset += seed.length) {
    bytes.set(seed.subarray(0, Math.min(seed.length, bytes.length - offset)), offset);
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
