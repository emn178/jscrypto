export class CryptoError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

export class DuplicateComponentError extends CryptoError {
  constructor(kind: string, name: string) {
    super(`Component already registered: ${kind}:${name}`);
  }
}

export class MissingComponentError extends CryptoError {
  constructor(kind: string, name: string) {
    super(`Component not found: ${kind}:${name}`);
  }
}

