export interface BlockSizeOptions {
  readonly max?: number;
}

export function assertBlockSize(blockSize: number, options: BlockSizeOptions = {}): void {
  const { max } = options;
  if (!Number.isInteger(blockSize) || blockSize <= 0) {
    throw new RangeError('blockSize must be a positive integer.');
  }
  if (max !== undefined && blockSize > max) {
    throw new RangeError(`blockSize must be an integer between 1 and ${max}.`);
  }
}

export function assertBlockMultiple(input: Uint8Array, blockSize: number, label: string): void {
  assertBlockSize(blockSize);
  if (input.length % blockSize !== 0) {
    throw new Error(`${label} input length must be a multiple of the block size.`);
  }
}

export function assertPaddedInput(input: Uint8Array, blockSize: number, label: string, options: BlockSizeOptions = {}): void {
  assertBlockSize(blockSize, options);
  if (input.length === 0 || input.length % blockSize !== 0) {
    throw new Error(`Invalid ${label} padded data.`);
  }
}

export function assertIv(blockSize: number, iv: Uint8Array | undefined, modeName: string): asserts iv is Uint8Array {
  if (!iv) {
    throw new Error(`${modeName} mode requires an IV.`);
  }
  if (iv.length !== blockSize) {
    throw new Error(`${modeName} IV length must match the cipher block size.`);
  }
}

export function getBlockPaddingLength(inputLength: number, blockSize: number): number {
  const remainder = inputLength % blockSize;
  return remainder === 0 ? blockSize : blockSize - remainder;
}
