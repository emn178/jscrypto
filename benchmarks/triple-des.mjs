import CryptoJS from 'crypto-js';
import { createDesJsCbc, desJsEde, hexToBytes, runCryptoJsBlockBenchmark } from './cryptojs-classic-suite.mjs';

runCryptoJsBlockBenchmark({
  title: 'TripleDES-CBC',
  cipher: 'TripleDES',
  cryptoJsCipher: CryptoJS.TripleDES,
  desJsCipher: createDesJsCbc(desJsEde),
  key: hexToBytes('0123456789abcdeffedcba98765432100011223344556677'),
  iv: hexToBytes('0102030405060708'),
  block: hexToBytes('0123456789abcdef'),
  defaultBytes: 320_000,
  defaultWarmupBytes: 32_000,
});
