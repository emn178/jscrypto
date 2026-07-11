import type { BlockCipher } from '@crypto/core';
import CryptoJS from 'crypto-js';

export interface CryptoJsBlockCipherOptions {
  readonly name: string;
  readonly key: Uint8Array;
  readonly blockSize: number;
  readonly algorithm: CryptoJsCipherFactory;
}

export interface CryptoJsCipherFactory {
  createEncryptor(key: CryptoJS.lib.WordArray): unknown;
  createDecryptor(key: CryptoJS.lib.WordArray): unknown;
}

interface CryptoJsBlockCipherAlgorithm {
  encryptBlock(words: number[], offset: number): void;
  decryptBlock(words: number[], offset: number): void;
}

export function createCryptoJsBlockCipher(options: CryptoJsBlockCipherOptions): BlockCipher {
  const { name, key, blockSize, algorithm } = options;
  const keyWords = bytesToWordArray(key);
  const encryptor = algorithm.createEncryptor(keyWords) as CryptoJsBlockCipherAlgorithm;
  const decryptor = algorithm.createDecryptor(keyWords) as CryptoJsBlockCipherAlgorithm;

  return {
    blockSize,

    encryptBlock(block) {
      assertBlock(block, blockSize, name);
      const words = bytesToWords(block);
      encryptor.encryptBlock(words, 0);
      return wordsToBytes(words, blockSize);
    },

    decryptBlock(block) {
      assertBlock(block, blockSize, name);
      const words = bytesToWords(block);
      decryptor.decryptBlock(words, 0);
      return wordsToBytes(words, blockSize);
    },
  };
}

export { CryptoJS };

function assertBlock(block: Uint8Array, blockSize: number, name: string): void {
  if (block.length !== blockSize) {
    throw new Error(`${name} block must be ${blockSize * 8} bits.`);
  }
}

export function bytesToWordArray(bytes: Uint8Array): CryptoJS.lib.WordArray {
  return CryptoJS.lib.WordArray.create(bytesToWords(bytes), bytes.length);
}

export function bytesToWords(bytes: Uint8Array): number[] {
  const words: number[] = [];
  for (let i = 0; i < bytes.length; i++) {
    words[i >>> 2] |= bytes[i] << (24 - (i % 4) * 8);
  }
  return words;
}

export function wordArrayToBytes(wordArray: CryptoJS.lib.WordArray): Uint8Array {
  return wordsToBytes(wordArray.words, wordArray.sigBytes);
}

export function wordsToBytes(words: number[], length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    bytes[i] = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
  }
  return bytes;
}
