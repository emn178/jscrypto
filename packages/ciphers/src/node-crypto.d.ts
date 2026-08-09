declare module 'node:crypto' {
  interface Cipher {
    setAutoPadding(autoPadding: boolean): this;
    update(data: Uint8Array): Uint8Array;
    final(): Uint8Array;
  }

  export function createCipheriv(algorithm: string, key: Uint8Array, iv: Uint8Array | null): Cipher;
  export function createDecipheriv(algorithm: string, key: Uint8Array, iv: Uint8Array | null): Cipher;
}
