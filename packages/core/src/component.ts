export type ComponentKind =
  | 'cipher'
  | 'mode'
  | 'padding'
  | 'kdf'
  | 'format'
  | 'preset'
  | 'hash'
  | 'aead';

export interface Component<
  Kind extends ComponentKind = ComponentKind,
  Name extends string = string,
> {
  readonly kind: Kind;
  readonly name: Name;
}

export type CipherComponent<Name extends string = string> =
  | BlockCipherComponent<Name>
  | StreamCipherComponent<Name>;

export interface BlockCipherComponent<Name extends string = string> extends Component<'cipher', Name> {
  readonly type: 'block';
  readonly blockSize: number;
  readonly keySizes: readonly number[];
  create(key: Uint8Array): BlockCipher;
}

export interface StreamCipherComponent<Name extends string = string> extends Component<'cipher', Name> {
  readonly type: 'stream';
  readonly keySizes?: readonly number[];
  createEncryptor(params: StreamCipherTransformParams): Transform;
  createDecryptor(params: StreamCipherTransformParams): Transform;
}

export interface BlockCipher {
  readonly blockSize: number;
  /**
   * Optional low-level single-block hook for modes that need per-block feedback.
   * Implementations must read from `input` at `inputOffset` and write exactly one
   * block to `output` at `outputOffset`.
   */
  encryptBlock?(input: Uint8Array, inputOffset: number, output: Uint8Array, outputOffset: number): void;
  /**
   * Optional low-level single-block hook for modes that need per-block feedback.
   * Implementations must read from `input` at `inputOffset` and write exactly one
   * block to `output` at `outputOffset`.
   */
  decryptBlock?(input: Uint8Array, inputOffset: number, output: Uint8Array, outputOffset: number): void;
  /**
   * Encrypts one or more complete blocks into `output`.
   * `output` must have the same length as `input` and may be the same buffer as `input`.
   */
  encrypt(input: Uint8Array, output: Uint8Array): Uint8Array;
  /**
   * Decrypts one or more complete blocks into `output`.
   * `output` must have the same length as `input` and may be the same buffer as `input`.
   */
  decrypt(input: Uint8Array, output: Uint8Array): Uint8Array;
}

export interface ModeComponent<Name extends string = string> extends Component<'mode', Name> {
  readonly requiresPadding?: boolean;
  getIvSize?(cipher: BlockCipherComponent): number;
  createEncryptor(params: BlockModeTransformParams): Transform;
  createDecryptor(params: BlockModeTransformParams): Transform;
}

export interface BlockModeTransformParams {
  cipher: BlockCipher;
  iv?: Uint8Array;
  options?: unknown;
}

export interface StreamCipherTransformParams {
  key: Uint8Array;
  options?: unknown;
}

export interface Transform {
  process(input: Uint8Array): Uint8Array;
  finalize(input?: Uint8Array): Uint8Array;
}

export interface PaddingComponent<Name extends string = string> extends Component<'padding', Name> {
  pad(input: Uint8Array, blockSize: number): Uint8Array;
  unpad(input: Uint8Array, blockSize: number): Uint8Array;
}

export interface HashComponent<Name extends string = string> extends Component<'hash', Name> {
  readonly blockSize: number;
  readonly digestSize: number;
  hash(input: Uint8Array): Uint8Array;
}

export interface KdfDeriveContext {
  getHash(name: string): HashComponent;
}

export interface KdfComponent<Name extends string = string> extends Component<'kdf', Name> {
  derive(params: unknown, context: KdfDeriveContext): Uint8Array;
}

export interface FormatComponent<Name extends string = string> extends Component<'format', Name> {
  readonly mediaType?: string;
  stringify(params: FormatStringifyParams): Uint8Array;
  parse(input: Uint8Array): FormatParseResult;
}

export interface FormatStringifyParams {
  ciphertext: Uint8Array;
  salt?: Uint8Array;
}

export interface FormatParseResult {
  ciphertext: Uint8Array;
  salt?: Uint8Array;
}

export interface PresetComponent<Name extends string = string> extends Component<'preset', Name> {
  components(): Iterable<AnyComponent>;
}

export interface AeadComponent<Name extends string = string> extends Component<'aead', Name> {
  readonly keySizes?: readonly number[];
  readonly nonceSizes?: readonly number[];
  readonly recommendedNonceSize?: number;
  readonly tagSizes?: readonly number[];
  create(params: AeadCreateParams, context: AeadCreateContext): AeadTransform;
}

export interface AeadCreateParams {
  key: Uint8Array;
  options?: unknown;
}

export interface AeadCipherTransformOptions {
  cipher: string;
  mode?: string;
  padding?: string;
  key: Uint8Array;
  [option: string]: unknown;
}

export interface AeadCreateContext {
  createEncryptor(options: AeadCipherTransformOptions): Transform;
  createDecryptor(options: AeadCipherTransformOptions): Transform;
  createBlockCipher(options: {
    cipher: string;
    key: Uint8Array;
  }): BlockCipher;
}

export interface AeadTransform {
  createSealer(params: AeadCreateSealerParams): Transform;
  createOpener(params: AeadCreateOpenerParams): Transform;
}

export interface AeadCreateSealerParams {
  nonce?: Uint8Array;
  aad?: Uint8Array;
  tagLength?: number;
  options?: unknown;
}

export interface AeadCreateOpenerParams {
  nonce?: Uint8Array;
  aad?: Uint8Array;
  /**
   * Detached authentication tag. When present, `tagLength` is ignored and
   * `tag.length` determines the tag size used for verification.
   */
  tag?: Uint8Array;
  tagLength?: number;
  options?: unknown;
}

export type AnyComponent =
  | CipherComponent
  | ModeComponent
  | PaddingComponent
  | KdfComponent
  | HashComponent
  | FormatComponent
  | PresetComponent
  | AeadComponent;
