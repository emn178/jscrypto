import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { registry } from '../packages/classic/dist/index.mjs';
import CryptoJS from 'crypto-js';
import desjs from 'des.js';

const DEFAULT_BYTES = 3_200_000;
const DEFAULT_WARMUP_BYTES = 320_000;

export function runCryptoJsBlockBenchmark({
  title,
  cipher,
  cryptoJsCipher,
  desJsCipher,
  key,
  iv,
  block,
  defaultBytes = DEFAULT_BYTES,
  defaultWarmupBytes = DEFAULT_WARMUP_BYTES,
}) {
  const options = parseOptions(process.argv.slice(2), title, block.length, defaultBytes, defaultWarmupBytes);
  const plaintext = repeatBytes(block, options.bytes);

  console.log(`${title} throughput benchmark`);
  console.log('Scope: CBC + NoPadding one-shot comparison against crypto-js.');
  console.log(`Node: ${process.version}`);
  console.log(`Plaintext: ${formatBytes(options.bytes)}`);
  console.log(`Warmup plaintext: ${formatBytes(options.warmupBytes)}`);
  console.log('');

  const jscryptoCiphertext = encryptJscryptoBlock(cipher, key, iv, plaintext);
  const cryptoJsCiphertext = encryptCryptoJsBlock(cryptoJsCipher, key, iv, plaintext);
  const desJsCiphertext = encryptDesJsBlock(desJsCipher, key, iv, plaintext);
  assert.deepEqual(Array.from(jscryptoCiphertext), Array.from(cryptoJsCiphertext), `${title} encrypt mismatch`);
  assert.deepEqual(Array.from(jscryptoCiphertext), Array.from(desJsCiphertext), `${title} des.js encrypt mismatch`);
  assert.deepEqual(Array.from(decryptJscryptoBlock(cipher, key, iv, jscryptoCiphertext)), Array.from(plaintext), `${title} jscrypto decrypt mismatch`);
  assert.deepEqual(Array.from(decryptCryptoJsBlock(cryptoJsCipher, key, iv, cryptoJsCiphertext)), Array.from(plaintext), `${title} crypto-js decrypt mismatch`);
  assert.deepEqual(Array.from(decryptDesJsBlock(desJsCipher, key, iv, desJsCiphertext)), Array.from(plaintext), `${title} des.js decrypt mismatch`);

  printTable(title, [
    runBlockSuite({ direction: 'encrypt', cipher, cryptoJsCipher, desJsCipher, key, iv, plaintext, ciphertext: jscryptoCiphertext, options }),
    runBlockSuite({ direction: 'decrypt', cipher, cryptoJsCipher, desJsCipher, key, iv, plaintext, ciphertext: jscryptoCiphertext, options }),
  ]);
}

export function runCryptoJsRc4Benchmark({
  title,
  cipher,
  key,
  seed,
  defaultBytes = DEFAULT_BYTES,
  defaultWarmupBytes = DEFAULT_WARMUP_BYTES,
}) {
  const options = parseOptions(process.argv.slice(2), title, 1, defaultBytes, defaultWarmupBytes);
  const plaintext = repeatBytes(seed, options.bytes);

  console.log(`${title} throughput benchmark`);
  console.log('Scope: one-shot stream cipher comparison against crypto-js.');
  console.log(`Node: ${process.version}`);
  console.log(`Plaintext: ${formatBytes(options.bytes)}`);
  console.log(`Warmup plaintext: ${formatBytes(options.warmupBytes)}`);
  console.log('');

  const jscryptoCiphertext = encryptJscryptoStream(cipher, key, plaintext);
  const cryptoJsCiphertext = encryptCryptoJsRc4(key, plaintext);
  assert.deepEqual(Array.from(jscryptoCiphertext), Array.from(cryptoJsCiphertext), `${title} encrypt mismatch`);
  assert.deepEqual(Array.from(decryptJscryptoStream(cipher, key, jscryptoCiphertext)), Array.from(plaintext), `${title} jscrypto decrypt mismatch`);
  assert.deepEqual(Array.from(decryptCryptoJsRc4(key, cryptoJsCiphertext)), Array.from(plaintext), `${title} crypto-js decrypt mismatch`);

  printTable(title, [
    runStreamSuite({ direction: 'encrypt', cipher, key, plaintext, ciphertext: jscryptoCiphertext, options }),
    runStreamSuite({ direction: 'decrypt', cipher, key, plaintext, ciphertext: jscryptoCiphertext, options }),
  ]);
}

function runBlockSuite({
  direction,
  cipher,
  cryptoJsCipher,
  desJsCipher,
  key,
  iv,
  plaintext,
  ciphertext,
  options,
}) {
  const measuredInput = direction === 'encrypt' ? plaintext : ciphertext;
  const warmupPlaintext = plaintext.subarray(0, options.warmupBytes);
  const warmupInput = direction === 'encrypt'
    ? warmupPlaintext
    : encryptJscryptoBlock(cipher, key, iv, warmupPlaintext);

  const jscrypto = measure({
    measuredBytes: options.bytes,
    warmupInput,
    measuredInput,
    fn(source) {
      const output = direction === 'encrypt'
        ? encryptJscryptoBlock(cipher, key, iv, source)
        : decryptJscryptoBlock(cipher, key, iv, source);
      return checksumBytes(output);
    },
  });

  const cryptojs = measure({
    measuredBytes: options.bytes,
    warmupInput,
    measuredInput,
    fn(source) {
      const output = direction === 'encrypt'
        ? encryptCryptoJsBlock(cryptoJsCipher, key, iv, source)
        : decryptCryptoJsBlock(cryptoJsCipher, key, iv, source);
      return checksumBytes(output);
    },
  });

  const desjs = measure({
    measuredBytes: options.bytes,
    warmupInput,
    measuredInput,
    fn(source) {
      const output = direction === 'encrypt'
        ? encryptDesJsBlock(desJsCipher, key, iv, source)
        : decryptDesJsBlock(desJsCipher, key, iv, source);
      return checksumBytes(output);
    },
  });

  return {
    direction,
    jscrypto,
    cryptojs,
    desjs,
    ratio: jscrypto.bytesPerSecond / cryptojs.bytesPerSecond,
    desjsRatio: jscrypto.bytesPerSecond / desjs.bytesPerSecond,
  };
}

function runStreamSuite({
  direction,
  cipher,
  key,
  plaintext,
  ciphertext,
  options,
}) {
  const measuredInput = direction === 'encrypt' ? plaintext : ciphertext;
  const warmupPlaintext = plaintext.subarray(0, options.warmupBytes);
  const warmupInput = direction === 'encrypt'
    ? warmupPlaintext
    : encryptJscryptoStream(cipher, key, warmupPlaintext);

  const jscrypto = measure({
    measuredBytes: options.bytes,
    warmupInput,
    measuredInput,
    fn(source) {
      const output = direction === 'encrypt'
        ? encryptJscryptoStream(cipher, key, source)
        : decryptJscryptoStream(cipher, key, source);
      return checksumBytes(output);
    },
  });

  const cryptojs = measure({
    measuredBytes: options.bytes,
    warmupInput,
    measuredInput,
    fn(source) {
      const output = direction === 'encrypt'
        ? encryptCryptoJsRc4(key, source)
        : decryptCryptoJsRc4(key, source);
      return checksumBytes(output);
    },
  });

  return {
    direction,
    jscrypto,
    cryptojs,
    ratio: jscrypto.bytesPerSecond / cryptojs.bytesPerSecond,
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

function encryptJscryptoBlock(cipher, key, iv, input) {
  return registry.encrypt({
    cipher,
    mode: 'CBC',
    padding: 'NoPadding',
    key,
    iv,
    plaintext: input,
  });
}

function decryptJscryptoBlock(cipher, key, iv, input) {
  return registry.decrypt({
    cipher,
    mode: 'CBC',
    padding: 'NoPadding',
    key,
    iv,
    ciphertext: input,
  });
}

function encryptJscryptoStream(cipher, key, input) {
  return registry.encrypt({
    cipher,
    key,
    plaintext: input,
  });
}

function decryptJscryptoStream(cipher, key, input) {
  return registry.decrypt({
    cipher,
    key,
    ciphertext: input,
  });
}

function encryptCryptoJsBlock(cryptoJsCipher, key, iv, input) {
  return bytesFromWordArray(cryptoJsCipher.encrypt(
    wordArrayFromBytes(input),
    wordArrayFromBytes(key),
    {
      iv: wordArrayFromBytes(iv),
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.NoPadding,
    },
  ).ciphertext);
}

function decryptCryptoJsBlock(cryptoJsCipher, key, iv, input) {
  return bytesFromWordArray(cryptoJsCipher.decrypt(
    CryptoJS.lib.CipherParams.create({ ciphertext: wordArrayFromBytes(input) }),
    wordArrayFromBytes(key),
    {
      iv: wordArrayFromBytes(iv),
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.NoPadding,
    },
  ));
}

function encryptDesJsBlock(desJsCipher, key, iv, input) {
  const transform = desJsCipher.create({
    type: 'encrypt',
    key,
    iv,
    padding: false,
  });
  return bytesFromArray(transform.update(input).concat(transform.final()));
}

function decryptDesJsBlock(desJsCipher, key, iv, input) {
  const transform = desJsCipher.create({
    type: 'decrypt',
    key,
    iv,
    padding: false,
  });
  return bytesFromArray(transform.update(input).concat(transform.final()));
}

function encryptCryptoJsRc4(key, input) {
  return bytesFromWordArray(CryptoJS.algo.RC4.createEncryptor(wordArrayFromBytes(key)).finalize(wordArrayFromBytes(input)));
}

function decryptCryptoJsRc4(key, input) {
  return bytesFromWordArray(CryptoJS.algo.RC4.createDecryptor(wordArrayFromBytes(key)).finalize(wordArrayFromBytes(input)));
}

function parseOptions(args, title, blockSize, defaultBytes, defaultWarmupBytes) {
  const options = {
    bytes: defaultBytes,
    warmupBytes: defaultWarmupBytes,
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
      printHelp(title);
      process.exit(0);
    } else {
      throw new Error(`Unknown option: ${arg}`);
    }
  }

  if (options.bytes % blockSize !== 0) {
    throw new Error(`bytes must be a multiple of ${blockSize}.`);
  }
  if (options.warmupBytes % blockSize !== 0) {
    throw new Error(`warmup-bytes must be a multiple of ${blockSize}.`);
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

function printHelp(title) {
  console.log(`Usage: npm run benchmark:${title.toLowerCase().replace(/ /g, '-')} -- [options]

Options:
  --bytes <n>          Number of measured plaintext bytes. Default: ${DEFAULT_BYTES}
  --warmup-bytes <n>   Number of warmup plaintext bytes per case. Default: ${DEFAULT_WARMUP_BYTES}
`);
}

function printTable(title, rows) {
  for (const row of rows) {
    console.log(`${title} ${row.direction}`);
    console.log(`  jscrypto   ${formatRate(row.jscrypto.bytesPerSecond).padStart(8)} MiB/s  ${row.ratio.toFixed(2)}x`);
    console.log(`  crypto-js  ${formatRate(row.cryptojs.bytesPerSecond).padStart(8)} MiB/s`);
    if (row.desjs) {
      console.log(`  des.js     ${formatRate(row.desjs.bytesPerSecond).padStart(8)} MiB/s  jscrypto/des.js ${row.desjsRatio.toFixed(2)}x`);
    }
    console.log('');
  }

  const checksum = rows.reduce(
    (acc, row) => (acc + row.jscrypto.checksum + row.cryptojs.checksum + (row.desjs?.checksum ?? 0)) >>> 0,
    0,
  );
  console.log(`Checksum: ${checksum}`);
}

function formatNumber(value) {
  return Math.round(value).toLocaleString();
}

function formatRate(bytesPerSecond) {
  const mibPerSecond = bytesPerSecond / 1024 / 1024;
  return (mibPerSecond < 10 ? mibPerSecond.toFixed(1) : formatNumber(mibPerSecond)).toLocaleString();
}

function formatBytes(bytes) {
  return `${(bytes / 1024 / 1024).toFixed(2)} MiB`;
}

export function hexToBytes(hex) {
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

function wordArrayFromBytes(bytes) {
  const words = [];
  for (let index = 0; index < bytes.length; index++) {
    words[index >>> 2] |= bytes[index] << (24 - (index & 3) * 8);
  }
  return CryptoJS.lib.WordArray.create(words, bytes.length);
}

function bytesFromWordArray(wordArray) {
  const bytes = new Uint8Array(wordArray.sigBytes);
  for (let index = 0; index < bytes.length; index++) {
    bytes[index] = (wordArray.words[index >>> 2] >>> (24 - (index & 3) * 8)) & 0xff;
  }
  return bytes;
}

function bytesFromArray(array) {
  return Uint8Array.from(array);
}

export function createDesJsCbc(cipher) {
  return desjs.CBC.instantiate(cipher);
}

export const desJsDes = desjs.DES;
export const desJsEde = desjs.EDE;

function checksumBytes(bytes) {
  let checksum = 0;
  for (let index = 0; index < bytes.length; index++) {
    checksum = (checksum + bytes[index]) >>> 0;
  }
  return checksum;
}
