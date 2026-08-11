import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  createRegistry,
  DuplicateComponentError,
  MissingComponentError,
} from '@jscrypto/core';
import { aes, cbc, pkcs7, rc4 } from '@jscrypto/suite';

function createFakeAeadComponent(name = 'Fake-AEAD') {
  const calls = { create: [] as unknown[], createSealer: [] as unknown[], createOpener: [] as unknown[], sealProcess: [] as unknown[], openProcess: [] as unknown[] };
  const component = {
    kind: 'aead' as const,
    name,
    create(params: unknown) {
      calls.create.push(params);
      return {
        createSealer(params: unknown) {
          calls.createSealer.push(params);
          return {
            process(input: Uint8Array) {
              calls.sealProcess.push(input);
              return new Uint8Array([1]);
            },
            finalize(input = new Uint8Array(0)) {
              if (input.length !== 0) {
                this.process(input);
              }
              return new Uint8Array([1, 2, 3]);
            },
          };
        },
        createOpener(params: unknown) {
          calls.createOpener.push(params);
          return {
            process(input: Uint8Array) {
              calls.openProcess.push(input);
              return new Uint8Array(0);
            },
            finalize(input = new Uint8Array(0)) {
              if (input.length !== 0) {
                this.process(input);
              }
              return new Uint8Array([4, 5]);
            },
          };
        },
      };
    },
  };
  return { component, calls };
}

test('registry.use registers a component of kind aead', () => {
  const { component } = createFakeAeadComponent();
  const registry = createRegistry().use(component);
  assert.equal(registry.has('aead', 'Fake-AEAD'), true);
  assert.equal(registry.get('aead', 'Fake-AEAD'), component);
  assert.deepEqual(registry.list('aead'), [component]);
});

test('duplicate aead component registration throws DuplicateComponentError', () => {
  const { component } = createFakeAeadComponent();
  const registry = createRegistry().use(component);
  assert.throws(() => registry.use(component), DuplicateComponentError);
  assert.throws(
    () => registry.use(component),
    /Component already registered: aead:Fake-AEAD/,
  );
});

test('missing aead component throws MissingComponentError', () => {
  const registry = createRegistry();
  assert.throws(
    () => registry.createAead({ algorithm: 'Missing-AEAD', key: new Uint8Array(16) }),
    MissingComponentError,
  );
  assert.throws(
    () => registry.createAead({ algorithm: 'Missing-AEAD', key: new Uint8Array(16) }),
    /Component not found: aead:Missing-AEAD/,
  );
  assert.equal(registry.has('aead', 'Missing-AEAD'), false);
});

test('createAead resolves the component by algorithm name and creates it with the key', () => {
  const { component, calls } = createFakeAeadComponent();
  const registry = createRegistry().use(component);
  const key = new Uint8Array([9, 9, 9]);

  registry.createAead({ algorithm: 'Fake-AEAD', key });

  assert.equal(calls.create.length, 1);
  assert.equal((calls.create[0] as { key: Uint8Array }).key, key);
});

test('facade seal/open forward operation options to the component', () => {
  const { component, calls } = createFakeAeadComponent();
  const registry = createRegistry().use(component);
  const key = new Uint8Array([9, 9, 9]);
  const aead = registry.createAead({ algorithm: 'Fake-AEAD', key });

  const nonce = new Uint8Array([1]);
  const aad = new Uint8Array([2]);
  const plaintext = new Uint8Array([3, 4]);
  const sealed = aead.seal(plaintext, { nonce, aad, tagLength: 8 });
  assert.deepEqual([...sealed], [1, 2, 3]);
  assert.equal(calls.createSealer.length, 1);
  assert.equal(calls.sealProcess[0], plaintext);
  assert.equal((calls.createSealer[0] as { nonce: Uint8Array }).nonce, nonce);
  assert.equal((calls.createSealer[0] as { aad: Uint8Array }).aad, aad);
  assert.equal((calls.createSealer[0] as { tagLength: number }).tagLength, 8);

  const ciphertext = new Uint8Array([5, 6]);
  const tag = new Uint8Array([7]);
  const opened = aead.open(ciphertext, { nonce, aad, tag, tagLength: 8 });
  assert.deepEqual([...opened], [4, 5]);
  assert.equal(calls.createOpener.length, 1);
  assert.equal(calls.openProcess[0], ciphertext);
  assert.equal((calls.createOpener[0] as { nonce: Uint8Array }).nonce, nonce);
  assert.equal((calls.createOpener[0] as { aad: Uint8Array }).aad, aad);
  assert.equal((calls.createOpener[0] as { tag: Uint8Array }).tag, tag);
  assert.equal((calls.createOpener[0] as { tagLength: number }).tagLength, 8);
});

test('facade createSealer/createOpener expose AEAD streaming transforms', () => {
  const { component, calls } = createFakeAeadComponent();
  const registry = createRegistry().use(component);
  const key = new Uint8Array([9, 9, 9]);
  const nonce = new Uint8Array([1]);
  const aad = new Uint8Array([2]);
  const tag = new Uint8Array([3]);
  const aead = registry.createAead({ algorithm: 'Fake-AEAD', key, extra: 'from-create' });

  const sealer = aead.createSealer({ nonce, aad, tagLength: 8, extra2: 'from-seal' });
  assert.deepEqual([...sealer.process(new Uint8Array([4]))], [1]);
  assert.deepEqual([...sealer.finalize(new Uint8Array([5]))], [1, 2, 3]);
  assert.equal((calls.createSealer[0] as { nonce: Uint8Array }).nonce, nonce);
  assert.equal((calls.createSealer[0] as { aad: Uint8Array }).aad, aad);
  assert.equal((calls.createSealer[0] as { tagLength: number }).tagLength, 8);
  assert.equal((calls.createSealer[0] as { options: { extra: string } }).options.extra, 'from-create');
  assert.equal((calls.createSealer[0] as { options: { extra2: string } }).options.extra2, 'from-seal');
  assert.deepEqual(calls.sealProcess, [new Uint8Array([4]), new Uint8Array([5])]);

  const opener = aead.createOpener({ nonce, aad, tag, extra3: 'from-open' });
  assert.deepEqual([...opener.process(new Uint8Array([6]))], []);
  assert.deepEqual([...opener.finalize(new Uint8Array([7]))], [4, 5]);
  assert.equal((calls.createOpener[0] as { nonce: Uint8Array }).nonce, nonce);
  assert.equal((calls.createOpener[0] as { aad: Uint8Array }).aad, aad);
  assert.equal((calls.createOpener[0] as { tag: Uint8Array }).tag, tag);
  assert.equal((calls.createOpener[0] as { options: { extra: string } }).options.extra, 'from-create');
  assert.equal((calls.createOpener[0] as { options: { extra3: string } }).options.extra3, 'from-open');
  assert.deepEqual(calls.openProcess, [new Uint8Array([6]), new Uint8Array([7])]);
});

test('facade methods do not depend on this binding', () => {
  const { component } = createFakeAeadComponent();
  const registry = createRegistry().use(component);
  const aead = registry.createAead({ algorithm: 'Fake-AEAD', key: new Uint8Array([1]) });
  const { seal, open, createSealer, createOpener } = aead;

  assert.deepEqual([...seal(new Uint8Array([1]))], [1, 2, 3]);
  assert.deepEqual([...open(new Uint8Array([2]))], [4, 5]);
  assert.deepEqual([...createSealer().finalize(new Uint8Array([3]))], [1, 2, 3]);
  assert.deepEqual([...createOpener().finalize(new Uint8Array([4]))], [4, 5]);
});

test('seal/open work with no operation options at all', () => {
  const { component, calls } = createFakeAeadComponent();
  const registry = createRegistry().use(component);
  const aead = registry.createAead({ algorithm: 'Fake-AEAD', key: new Uint8Array([1]) });

  aead.seal(new Uint8Array([1]));
  aead.open(new Uint8Array([1]));

  assert.equal((calls.createSealer[0] as { nonce: undefined }).nonce, undefined);
  assert.equal((calls.createOpener[0] as { tag: undefined }).tag, undefined);
});

test('unknown extra fields in creation and operation options are ignored by core', () => {
  const { component, calls } = createFakeAeadComponent();
  const registry = createRegistry().use(component);
  const key = new Uint8Array([1]);
  const aead = registry.createAead({
    algorithm: 'Fake-AEAD',
    key,
    mode: 'CTR',
    extra: 'from-create',
  });

  aead.seal(new Uint8Array(0), {
    nonce: new Uint8Array([1]),
    mode: 'CBC',
    padding: 'Pkcs7',
    cipher: 'AES',
    iv: new Uint8Array([9]),
    extra2: 'from-seal',
  });

  assert.equal((calls.createSealer[0] as { options: { mode: string } }).options.mode, 'CBC');
  assert.equal((calls.createSealer[0] as { options: { padding: string } }).options.padding, 'Pkcs7');
  assert.equal((calls.createSealer[0] as { options: { cipher: string } }).options.cipher, 'AES');
  assert.deepEqual((calls.createSealer[0] as { options: { iv: Uint8Array } }).options.iv, new Uint8Array([9]));
  assert.equal((calls.createSealer[0] as { options: { extra: string } }).options.extra, 'from-create');
  assert.equal((calls.createSealer[0] as { options: { extra2: string } }).options.extra2, 'from-seal');

  aead.open(new Uint8Array(0), { padding: 'Pkcs7', extra3: 'from-open' });
  assert.equal((calls.createOpener[0] as { options: { padding: string } }).options.padding, 'Pkcs7');
  assert.equal((calls.createOpener[0] as { options: { extra3: string } }).options.extra3, 'from-open');
  assert.equal((calls.createOpener[0] as { options: { extra: string } }).options.extra, 'from-create');
});

test('operation options cannot override the reserved algorithm or key fields', () => {
  const { component } = createFakeAeadComponent();
  const registry = createRegistry().use(component);
  const aead = registry.createAead({ algorithm: 'Fake-AEAD', key: new Uint8Array([1]) });

  assert.throws(
    () => aead.seal(new Uint8Array(0), { algorithm: 'Other-AEAD' }),
    /operation options must not override reserved key: algorithm/,
  );
  assert.throws(
    () => aead.open(new Uint8Array(0), { key: new Uint8Array([2]) }),
    /operation options must not override reserved key: key/,
  );
});

test('registry does not expose top-level seal/open helpers in this MVP', () => {
  const registry = createRegistry();
  assert.equal((registry as { seal?: unknown }).seal, undefined);
  assert.equal((registry as { open?: unknown }).open, undefined);
});

test('createAead passes registry helpers to components that use them', () => {
  const registry = createRegistry([aes, cbc, pkcs7, rc4]);
  const key = new Uint8Array(16);
  const iv = new Uint8Array(16);

  const component = {
    kind: 'aead' as const,
    name: 'Context-AEAD',
    create(
      _params: unknown,
      context: {
        createEncryptor: (options: Record<string, unknown>) => unknown;
        createDecryptor: (options: Record<string, unknown>) => unknown;
        createBlockCipher: (options: { cipher: string; key: Uint8Array }) => unknown;
      },
    ) {
      context.createEncryptor({ cipher: 'AES', mode: 'CBC', padding: 'Pkcs7', key, iv });
      context.createDecryptor({ cipher: 'AES', mode: 'CBC', padding: 'Pkcs7', key, iv });
      context.createBlockCipher({ cipher: 'AES', key });
      assert.throws(
        () => context.createBlockCipher({ cipher: 'RC4', key }),
        /Expected a block cipher component: RC4/,
      );
      return {
        createSealer() {
          return { process: () => new Uint8Array(0), finalize: () => new Uint8Array(0) };
        },
        createOpener() {
          return { process: () => new Uint8Array(0), finalize: () => new Uint8Array(0) };
        },
      };
    },
  };

  // Test double intentionally uses a loose context signature.
  registry.use(component as never);
  registry.createAead({ algorithm: 'Context-AEAD', key });
});
