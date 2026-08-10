declare module 'node:crypto' {
  interface Cipher {
    setAutoPadding(autoPadding: boolean): this;
    update(data: Uint8Array): Uint8Array;
    final(): Uint8Array;
  }

  interface CipherGCM extends Cipher {
    setAAD(buffer: Uint8Array): this;
    getAuthTag(): Uint8Array;
  }

  interface DecipherGCM extends Cipher {
    setAAD(buffer: Uint8Array): this;
    setAuthTag(buffer: Uint8Array): this;
  }

  interface CipherGCMTypes {
    authTagLength: number;
  }

  export function createCipheriv(algorithm: string, key: Uint8Array, iv: Uint8Array | null): Cipher;
  export function createCipheriv(
    algorithm: string,
    key: Uint8Array,
    iv: Uint8Array,
    options: CipherGCMTypes,
  ): CipherGCM;
  export function createDecipheriv(algorithm: string, key: Uint8Array, iv: Uint8Array | null): Cipher;
  export function createDecipheriv(
    algorithm: string,
    key: Uint8Array,
    iv: Uint8Array,
    options: CipherGCMTypes,
  ): DecipherGCM;
}
