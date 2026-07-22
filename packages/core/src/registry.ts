import type { AnyComponent, Component, ComponentKind, HashComponent, PresetComponent } from './component.js';
import { DuplicateComponentError, MissingComponentError } from './errors.js';
import type {
  CreateDerivedKeyCipherOptions,
  DeriveOptions,
  DerivedKeyCipherFacade,
} from './derived-key.js';
import { createDerivedKeyCipher, derive } from './derived-key.js';
import type { CreatePassphraseCipherOptions, PassphraseCipherFacade } from './passphrase.js';
import { createPassphraseCipher } from './passphrase.js';
import type { CreateTransformOptions } from './transform.js';
import { createDecryptor, createEncryptor } from './transform.js';
import type { Transform } from './component.js';

export interface Registry {
  use(component: AnyComponent): Registry;
  useHash(hash: HashComponent): Registry;
  getHash(name: string): HashComponent;
  has(kind: ComponentKind, name: string): boolean;
  get<Kind extends ComponentKind, T extends Component<Kind>>(kind: Kind, name: string): T;
  list(kind?: ComponentKind): AnyComponent[];
  createCipher(options: CreateTransformOptions): CipherFacade;
  derive(options: DeriveOptions): Uint8Array;
  createDerivedKeyCipher(options: CreateDerivedKeyCipherOptions): DerivedKeyCipherFacade;
  /**
   * @deprecated Use createDerivedKeyCipher({ ..., kdf: { ..., input } }) instead.
   */
  createPassphraseCipher(options: CreatePassphraseCipherOptions): PassphraseCipherFacade;
  encrypt(options: CreateTransformOptions & { plaintext: Uint8Array }): Uint8Array;
  decrypt(options: CreateTransformOptions & { ciphertext: Uint8Array }): Uint8Array;
  createEncryptor(options: CreateTransformOptions): Transform;
  createDecryptor(options: CreateTransformOptions): Transform;
}

export interface CipherFacade {
  encrypt(plaintext: Uint8Array): Uint8Array;
  decrypt(ciphertext: Uint8Array): Uint8Array;
  createEncryptor(): Transform;
  createDecryptor(): Transform;
}

export function createRegistry(components: Iterable<AnyComponent> = []): Registry {
  const entries = new Map<string, AnyComponent>();

  const normalizeName = (kind: ComponentKind, name: string) => (
    kind === 'hash' ? name.replace(/-/g, '').toUpperCase() : name
  );
  const key = (kind: ComponentKind, name: string) => `${kind}:${normalizeName(kind, name)}`;

  const registry: Registry = {
    use(component) {
      if (component.kind === 'preset') {
        for (const item of (component as PresetComponent).components()) {
          registry.use(item);
        }
        return registry;
      }

      const entryKey = key(component.kind, component.name);
      if (entries.has(entryKey)) {
        throw new DuplicateComponentError(component.kind, component.name);
      }
      entries.set(entryKey, component);
      return registry;
    },

    useHash(hash) {
      return registry.use(hash);
    },

    getHash(name) {
      const component = entries.get(key('hash', name));
      if (!component) {
        throw new Error(`Hash not registered: ${normalizeName('hash', name)}.`);
      }
      return component as HashComponent;
    },

    has(kind, name) {
      return entries.has(key(kind, name));
    },

    get(kind, name) {
      const component = entries.get(key(kind, name));
      if (!component) {
        throw new MissingComponentError(kind, name);
      }
      return component as never;
    },

    list(kind) {
      const components = [...entries.values()];
      return kind ? components.filter((component) => component.kind === kind) : components;
    },

    createCipher(options) {
      return {
        encrypt(plaintext) {
          return createEncryptor(registry, options).finalize(plaintext);
        },

        decrypt(ciphertext) {
          return createDecryptor(registry, options).finalize(ciphertext);
        },

        createEncryptor() {
          return createEncryptor(registry, options);
        },

        createDecryptor() {
          return createDecryptor(registry, options);
        },
      };
    },

    derive(options) {
      return derive(registry, options);
    },

    createDerivedKeyCipher(options) {
      return createDerivedKeyCipher(registry, options);
    },

    createPassphraseCipher(options) {
      return createPassphraseCipher(registry, options);
    },

    encrypt(options) {
      return createEncryptor(registry, options).finalize(options.plaintext);
    },

    decrypt(options) {
      return createDecryptor(registry, options).finalize(options.ciphertext);
    },

    createEncryptor(options) {
      return createEncryptor(registry, options);
    },

    createDecryptor(options) {
      return createDecryptor(registry, options);
    },
  };

  for (const component of components) {
    registry.use(component);
  }

  return registry;
}
