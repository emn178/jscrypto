import { hexToBytes, runCryptoJsRc4Benchmark } from './cryptojs-classic-suite.mjs';

runCryptoJsRc4Benchmark({
  title: 'RC4',
  cipher: 'RC4',
  key: hexToBytes('7365637265742d6b6579'),
  seed: hexToBytes('00112233445566778899aabbccddeeff'),
});
