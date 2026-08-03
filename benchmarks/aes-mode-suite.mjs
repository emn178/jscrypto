import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { registry } from '../packages/classic/dist/index.mjs';

const BLOCK_SIZE = 16;
const DEFAULT_BYTES = 3_200_000;
const DEFAULT_WARMUP_BYTES = 320_000;

const key = hexToBytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
const iv = hexToBytes('101112131415161718191a1b1c1d1e1f');
const block = hexToBytes('00112233445566778899aabbccddeeff');

export function runAesModeBenchmark({
  mode,
  nobleCipher,
  padding,
}) {
  const options = parseOptions(process.argv.slice(2), mode);
  const plaintext = repeatBytes(block, options.bytes);

  console.log(`AES-${mode} throughput benchmark`);
  console.log('Scope: one-shot AES-256 mode comparison. jscrypto AES blocks use @noble/ciphers; this mainly measures mode/facade overhead.');
  console.log(`Node: ${process.version}`);
  console.log(`Plaintext: ${formatBytes(options.bytes)}`);
  console.log(`Warmup plaintext: ${formatBytes(options.warmupBytes)}`);
  console.log('');

  const jscryptoCiphertext = encryptJscrypto(mode, padding, plaintext);
  const nobleCiphertext = encryptNoble(nobleCipher, plaintext);
  assert.deepEqual(Array.from(jscryptoCiphertext), Array.from(nobleCiphertext), `AES-${mode} encrypt mismatch`);
  assert.deepEqual(Array.from(decryptJscrypto(mode, padding, jscryptoCiphertext)), Array.from(plaintext), `AES-${mode} jscrypto decrypt mismatch`);
  assert.deepEqual(Array.from(decryptNoble(nobleCipher, nobleCiphertext)), Array.from(plaintext), `AES-${mode} noble decrypt mismatch`);

  printTable([
    runSuite({ direction: 'encrypt', mode, padding, nobleCipher, plaintext, ciphertext: jscryptoCiphertext, options }),
    runSuite({ direction: 'decrypt', mode, padding, nobleCipher, plaintext, ciphertext: jscryptoCiphertext, options }),
  ]);
}

function runSuite({
  direction,
  mode,
  padding,
  nobleCipher,
  plaintext,
  ciphertext,
  options,
}) {
  const measuredInput = direction === 'encrypt' ? plaintext : ciphertext;
  const warmupPlaintext = plaintext.subarray(0, options.warmupBytes);
  const warmupInput = direction === 'encrypt'
    ? warmupPlaintext
    : encryptJscrypto(mode, padding, warmupPlaintext);

  const jscrypto = measure({
    measuredBytes: options.bytes,
    warmupInput,
    measuredInput,
    fn(source) {
      const output = direction === 'encrypt'
        ? encryptJscrypto(mode, padding, source)
        : decryptJscrypto(mode, padding, source);
      return checksumBytes(output);
    },
  });

  const jscryptoMutable = measure({
    measuredBytes: options.bytes,
    warmupInput,
    measuredInput,
    fn(source) {
      const mutableSource = source.slice();
      const output = direction === 'encrypt'
        ? encryptJscrypto(mode, padding, mutableSource, true)
        : decryptJscrypto(mode, padding, mutableSource, true);
      return checksumBytes(output);
    },
  });

  const noble = measure({
    measuredBytes: options.bytes,
    warmupInput,
    measuredInput,
    fn(source) {
      const output = direction === 'encrypt'
        ? encryptNoble(nobleCipher, source)
        : decryptNoble(nobleCipher, source);
      return checksumBytes(output);
    },
  });

  return {
    mode,
    direction,
    jscrypto,
    jscryptoMutable,
    noble,
    ratio: jscrypto.bytesPerSecond / noble.bytesPerSecond,
    mutableRatio: jscryptoMutable.bytesPerSecond / noble.bytesPerSecond,
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

function encryptJscrypto(mode, padding, input, mutableInput = false) {
  return registry.encrypt(createJscryptoOptions({
    mode,
    padding,
    mutableInput,
    plaintext: input,
  }));
}

function decryptJscrypto(mode, padding, input, mutableInput = false) {
  return registry.decrypt(createJscryptoOptions({
    mode,
    padding,
    mutableInput,
    ciphertext: input,
  }));
}

function createJscryptoOptions(options) {
  return {
    cipher: 'AES',
    key,
    iv,
    ...options,
  };
}

function encryptNoble(nobleCipher, input) {
  return nobleCipher(key, iv).encrypt(input);
}

function decryptNoble(nobleCipher, input) {
  return nobleCipher(key, iv).decrypt(input);
}

function parseOptions(args, mode) {
  const options = {
    bytes: DEFAULT_BYTES,
    warmupBytes: DEFAULT_WARMUP_BYTES,
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
    } else if (arg === '--help' || arg === '-h') {
      printHelp(mode);
      process.exit(0);
    } else {
      throw new Error(`Unknown option: ${arg}`);
    }
  }

  if (options.bytes % BLOCK_SIZE !== 0) {
    throw new Error(`bytes must be a multiple of ${BLOCK_SIZE}.`);
  }
  if (options.warmupBytes % BLOCK_SIZE !== 0) {
    throw new Error(`warmup-bytes must be a multiple of ${BLOCK_SIZE}.`);
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

function printHelp(mode) {
  console.log(`Usage: npm run benchmark:aes-${mode.toLowerCase()} -- [options]

Options:
  --bytes <n>          Number of measured plaintext bytes. Default: ${DEFAULT_BYTES}
  --warmup-bytes <n>   Number of warmup plaintext bytes per case. Default: ${DEFAULT_WARMUP_BYTES}
`);
}

function printTable(rows) {
  for (const row of rows) {
    console.log(`AES-256-${row.mode} ${row.direction}`);
    console.log(`  jscrypto          ${formatNumber(row.jscrypto.bytesPerSecond / 1024 / 1024).padStart(6)} MiB/s  ${row.ratio.toFixed(2)}x`);
    console.log(`  jscrypto mutable  ${formatNumber(row.jscryptoMutable.bytesPerSecond / 1024 / 1024).padStart(6)} MiB/s  ${row.mutableRatio.toFixed(2)}x`);
    console.log(`  noble             ${formatNumber(row.noble.bytesPerSecond / 1024 / 1024).padStart(6)} MiB/s`);
    console.log('');
  }

  const checksum = rows.reduce(
    (acc, row) => (acc + row.jscrypto.checksum + row.jscryptoMutable.checksum + row.noble.checksum) >>> 0,
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
