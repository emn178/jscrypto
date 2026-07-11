import type { ModeComponent } from '@jscrypto/core';

export const gcm: ModeComponent<'GCM'> = {
  kind: 'mode',
  name: 'GCM',
  aead: true,
  requiredBlockSize: 16,
  requiresPadding: false,
  createEncryptor() {
    throw new Error('GCM mode is not implemented yet.');
  },
  createDecryptor() {
    throw new Error('GCM mode is not implemented yet.');
  },
};
