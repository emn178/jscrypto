import type { StreamCipherComponent, Transform } from '@crypto/core';

export interface Rc4Options {
  readonly drop?: number;
}

export const rc4: StreamCipherComponent<'RC4'> = {
  kind: 'cipher',
  name: 'RC4',
  type: 'stream',
  createEncryptor({ key, options }) {
    return createRc4Transform(key, getDrop(options, 0));
  },
  createDecryptor({ key, options }) {
    return createRc4Transform(key, getDrop(options, 0));
  },
};

export const rc4Drop: StreamCipherComponent<'RC4Drop'> = {
  kind: 'cipher',
  name: 'RC4Drop',
  type: 'stream',
  createEncryptor({ key, options }) {
    return createRc4Transform(key, getDrop(options, 192));
  },
  createDecryptor({ key, options }) {
    return createRc4Transform(key, getDrop(options, 192));
  },
};

export function createRc4Transform(key: Uint8Array, drop = 0): Transform {
  assertKey(key);
  assertDrop(drop);

  const state = createInitialState(key);
  for (let n = 0; n < drop; n++) {
    nextByte(state);
  }

  let finalized = false;

  const processInput = (input: Uint8Array): Uint8Array => {
      const output = new Uint8Array(input.length);
      for (let i = 0; i < input.length; i++) {
        output[i] = input[i] ^ nextByte(state);
      }
      return output;
  };

  return {
    process(input) {
      assertNotFinalized(finalized);
      return processInput(input);
    },

    finalize(input = new Uint8Array()) {
      assertNotFinalized(finalized);
      finalized = true;
      return input.length === 0 ? new Uint8Array() : processInput(input);
    },
  };
}

interface Rc4State {
  readonly s: Uint8Array;
  i: number;
  j: number;
}

function createInitialState(key: Uint8Array): Rc4State {
  const s = new Uint8Array(256);
  for (let i = 0; i < s.length; i++) {
    s[i] = i;
  }

  let j = 0;
  for (let i = 0; i < s.length; i++) {
    j = (j + s[i] + key[i % key.length]) & 0xff;
    swap(s, i, j);
  }

  return { s, i: 0, j: 0 };
}

function nextByte(state: Rc4State): number {
  const { s } = state;
  state.i = (state.i + 1) & 0xff;
  state.j = (state.j + s[state.i]) & 0xff;
  swap(s, state.i, state.j);
  return s[(s[state.i] + s[state.j]) & 0xff];
}

function swap(bytes: Uint8Array, a: number, b: number): void {
  const value = bytes[a];
  bytes[a] = bytes[b];
  bytes[b] = value;
}

function getDrop(options: unknown, defaultDrop: number): number {
  if (!isRc4Options(options) || options.drop === undefined) {
    return defaultDrop;
  }
  return options.drop;
}

function isRc4Options(options: unknown): options is Rc4Options {
  return typeof options === 'object' && options !== null;
}

function assertKey(key: Uint8Array): void {
  if (key.length < 5) {
    throw new Error('RC4 key should be greater or equal than 40 bits.');
  }
}

function assertDrop(drop: number): void {
  if (!Number.isInteger(drop) || drop < 0) {
    throw new RangeError('RC4 drop must be a non-negative integer.');
  }
}

function assertNotFinalized(finalized: boolean): void {
  if (finalized) {
    throw new Error('Transform is already finalized.');
  }
}
