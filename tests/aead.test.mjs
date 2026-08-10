import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  createRegistry,
  DuplicateComponentError,
  MissingComponentError,
} from '@jscrypto/core';

function createFakeAeadComponent(name = 'Fake-AEAD') {
  const calls = { create: [], seal: [], open: [] };
  const component = {
    kind: 'aead',
    name,
    create(params) {
      calls.create.push(params);
      return {
        seal(params) {
          calls.seal.push(params);
          return new Uint8Array([1, 2, 3]);
        },
        open(params) {
          calls.open.push(params);
          return new Uint8Array([4, 5]);
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
  assert.equal(calls.create[0].key, key);
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
  assert.equal(calls.seal.length, 1);
  assert.equal(calls.seal[0].plaintext, plaintext);
  assert.equal(calls.seal[0].nonce, nonce);
  assert.equal(calls.seal[0].aad, aad);
  assert.equal(calls.seal[0].tagLength, 8);

  const ciphertext = new Uint8Array([5, 6]);
  const tag = new Uint8Array([7]);
  const opened = aead.open(ciphertext, { nonce, aad, tag, tagLength: 8 });
  assert.deepEqual([...opened], [4, 5]);
  assert.equal(calls.open.length, 1);
  assert.equal(calls.open[0].ciphertext, ciphertext);
  assert.equal(calls.open[0].nonce, nonce);
  assert.equal(calls.open[0].aad, aad);
  assert.equal(calls.open[0].tag, tag);
  assert.equal(calls.open[0].tagLength, 8);
});

test('seal/open work with no operation options at all', () => {
  const { component, calls } = createFakeAeadComponent();
  const registry = createRegistry().use(component);
  const aead = registry.createAead({ algorithm: 'Fake-AEAD', key: new Uint8Array([1]) });

  aead.seal(new Uint8Array([1]));
  aead.open(new Uint8Array([1]));

  assert.equal(calls.seal[0].nonce, undefined);
  assert.equal(calls.open[0].tag, undefined);
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

  // Core does not throw for unrecognized extension fields; it forwards them
  // through `options` so a component may opt in to reading them.
  // AEAD does not reuse the cipher-facade reserved list (mode/padding/...).
  assert.equal(calls.seal[0].options.mode, 'CBC');
  assert.equal(calls.seal[0].options.padding, 'Pkcs7');
  assert.equal(calls.seal[0].options.cipher, 'AES');
  assert.deepEqual(calls.seal[0].options.iv, new Uint8Array([9]));
  assert.equal(calls.seal[0].options.extra, 'from-create');
  assert.equal(calls.seal[0].options.extra2, 'from-seal');

  aead.open(new Uint8Array(0), { padding: 'Pkcs7', extra3: 'from-open' });
  assert.equal(calls.open[0].options.padding, 'Pkcs7');
  assert.equal(calls.open[0].options.extra3, 'from-open');
  assert.equal(calls.open[0].options.extra, 'from-create');
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
  assert.equal(registry.seal, undefined);
  assert.equal(registry.open, undefined);
});
