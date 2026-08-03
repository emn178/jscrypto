import { ctr as nobleCtr } from '@noble/ciphers/aes.js';
import { runAesModeBenchmark } from './aes-mode-suite.mjs';

runAesModeBenchmark({
  mode: 'CTR',
  nobleCipher(key, iv) {
    return nobleCtr(key, iv);
  },
});
