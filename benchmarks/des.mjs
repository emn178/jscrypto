import CryptoJS from 'crypto-js';
import { createDesJsCbc, desJsDes, hexToBytes, runCryptoJsBlockBenchmark } from './cryptojs-classic-suite.mjs';

runCryptoJsBlockBenchmark({
  title: 'DES-CBC',
  cipher: 'DES',
  cryptoJsCipher: CryptoJS.DES,
  desJsCipher: createDesJsCbc(desJsDes),
  key: hexToBytes('133457799bbcdff1'),
  iv: hexToBytes('0102030405060708'),
  block: hexToBytes('0123456789abcdef'),
  defaultBytes: 320_000,
  defaultWarmupBytes: 32_000,
});
