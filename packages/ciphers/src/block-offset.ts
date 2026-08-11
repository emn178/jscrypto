import type { BlockCipher } from '@jscrypto/core';

export function encryptWithBlockOffset(
  cipher: BlockCipher,
  input: Uint8Array,
  inputOffset: number,
  output: Uint8Array,
  outputOffset: number,
): void {
  if (cipher.encryptBlock) {
    cipher.encryptBlock(input, inputOffset, output, outputOffset);
    return;
  }

  cipher.encrypt(
    input.subarray(inputOffset, inputOffset + cipher.blockSize),
    output.subarray(outputOffset, outputOffset + cipher.blockSize),
  );
}

export function decryptWithBlockOffset(
  cipher: BlockCipher,
  input: Uint8Array,
  inputOffset: number,
  output: Uint8Array,
  outputOffset: number,
): void {
  if (cipher.decryptBlock) {
    cipher.decryptBlock(input, inputOffset, output, outputOffset);
    return;
  }

  cipher.decrypt(
    input.subarray(inputOffset, inputOffset + cipher.blockSize),
    output.subarray(outputOffset, outputOffset + cipher.blockSize),
  );
}
