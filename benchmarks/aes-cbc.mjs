import { cbc as nobleCbc } from '@noble/ciphers/aes.js';
import { runAesModeBenchmark } from './aes-mode-suite.mjs';

runAesModeBenchmark({
  mode: 'CBC',
  padding: 'NoPadding',
  nobleCipher(key, iv) {
    return nobleCbc(key, iv, { disablePadding: true });
  },
});
