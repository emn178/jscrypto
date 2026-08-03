import { cfb as nobleCfb } from '@noble/ciphers/aes.js';
import { runAesModeBenchmark } from './aes-mode-suite.mjs';

runAesModeBenchmark({
  mode: 'CFB',
  nobleCipher(key, iv) {
    return nobleCfb(key, iv);
  },
});
