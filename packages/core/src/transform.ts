import type { BlockCipherComponent, CipherComponent, ModeComponent, PaddingComponent, Transform } from './component.js';
import type { Registry } from './registry.js';
import { concatBytes } from './bytes.js';

export interface CreateTransformOptions {
  cipher: string;
  mode?: string;
  padding?: string;
  key: Uint8Array;
  iv?: Uint8Array;
  [option: string]: unknown;
}

export function createEncryptor(registry: Registry, options: CreateTransformOptions): Transform {
  const cipher = registry.get<'cipher', CipherComponent>('cipher', options.cipher);
  if (cipher.type === 'stream') {
    return createStreamEncryptor(cipher.createEncryptor({
      key: options.key,
      options,
    }));
  }

  const { mode, padding } = resolveBlockOptions(registry, options);
  const blockCipher = cipher.create(options.key);

  const modeEncryptor = mode.createEncryptor({
    cipher: blockCipher,
    iv: options.iv,
    options,
  });

  if (mode.requiresPadding === false) {
    return createStreamEncryptor(modeEncryptor);
  }
  const blockPadding = padding as PaddingComponent;

  let finalized = false;
  let pending: Uint8Array = new Uint8Array(0);

  return {
    process(input) {
      assertNotFinalized(finalized);
      const data = concatBytes(pending, input);
      const processLength = data.length - (data.length % blockCipher.blockSize);
      pending = data.slice(processLength);
      return processLength === 0 ? new Uint8Array(0) : modeEncryptor.process(data.subarray(0, processLength));
    },

    finalize(input = new Uint8Array(0)) {
      assertNotFinalized(finalized);
      const processed = input.length === 0 ? new Uint8Array(0) : this.process(input);
      finalized = true;
      const finalBlock = blockPadding.pad(pending, blockCipher.blockSize);
      pending = new Uint8Array(0);
      return concatBytes(processed, modeEncryptor.finalize(finalBlock));
    },
  };
}

export function createDecryptor(registry: Registry, options: CreateTransformOptions): Transform {
  const cipher = registry.get<'cipher', CipherComponent>('cipher', options.cipher);
  if (cipher.type === 'stream') {
    return createStreamDecryptor(cipher.createDecryptor({
      key: options.key,
      options,
    }));
  }

  const { mode, padding } = resolveBlockOptions(registry, options);
  const blockCipher = cipher.create(options.key);

  const modeDecryptor = mode.createDecryptor({
    cipher: blockCipher,
    iv: options.iv,
    options,
  });

  if (mode.requiresPadding === false) {
    return createStreamDecryptor(modeDecryptor);
  }
  const blockPadding = padding as PaddingComponent;

  let finalized = false;
  let pending: Uint8Array = new Uint8Array(0);
  let plaintextPending: Uint8Array = new Uint8Array(0);

  return {
    process(input) {
      assertNotFinalized(finalized);
      const data = concatBytes(pending, input);
      const processLength = data.length - (data.length % blockCipher.blockSize);
      pending = data.slice(processLength);

      if (processLength === 0) {
        return new Uint8Array(0);
      }

      const decrypted = modeDecryptor.process(data.subarray(0, processLength));
      const output = plaintextPending;
      plaintextPending = decrypted;
      return output;
    },

    finalize(input = new Uint8Array(0)) {
      assertNotFinalized(finalized);
      const processed = input.length === 0 ? new Uint8Array(0) : this.process(input);
      finalized = true;
      if (pending.length !== 0) {
        blockPadding.unpad(pending, blockCipher.blockSize);
      }
      const finalPlaintext = blockPadding.unpad(plaintextPending, blockCipher.blockSize);
      pending = new Uint8Array(0);
      plaintextPending = new Uint8Array(0);
      return concatBytes(processed, finalPlaintext, modeDecryptor.finalize());
    },
  };
}

function createStreamEncryptor(modeEncryptor: Transform): Transform {
  let finalized = false;

  return {
    process(input) {
      assertNotFinalized(finalized);
      return modeEncryptor.process(input);
    },

    finalize(input = new Uint8Array(0)) {
      assertNotFinalized(finalized);
      finalized = true;
      return concatBytes(
        input.length === 0 ? new Uint8Array(0) : modeEncryptor.process(input),
        modeEncryptor.finalize(),
      );
    },
  };
}

function createStreamDecryptor(modeDecryptor: Transform): Transform {
  let finalized = false;

  return {
    process(input) {
      assertNotFinalized(finalized);
      return modeDecryptor.process(input);
    },

    finalize(input = new Uint8Array(0)) {
      assertNotFinalized(finalized);
      finalized = true;
      return concatBytes(
        input.length === 0 ? new Uint8Array(0) : modeDecryptor.process(input),
        modeDecryptor.finalize(),
      );
    },
  };
}

function resolveBlockOptions(registry: Registry, options: CreateTransformOptions): {
  cipher: BlockCipherComponent;
  mode: ModeComponent;
  padding?: PaddingComponent;
} {
  if (!options.mode) {
    throw new Error(`${options.cipher} block cipher requires a mode.`);
  }

  const mode = registry.get<'mode', ModeComponent>('mode', options.mode);
  let padding: PaddingComponent | undefined;
  if (mode.requiresPadding !== false) {
    if (!options.padding) {
      throw new Error(`${options.cipher} block cipher requires padding.`);
    }
    padding = registry.get<'padding', PaddingComponent>('padding', options.padding);
  }

  return {
    cipher: registry.get<'cipher', BlockCipherComponent>('cipher', options.cipher),
    mode,
    padding,
  };
}

function assertNotFinalized(finalized: boolean): void {
  if (finalized) {
    throw new Error('Transform is already finalized.');
  }
}
