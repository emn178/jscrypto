export type ComponentKind = 'cipher' | 'mode' | 'padding' | 'kdf' | 'format' | 'preset';

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
  encryptBlock(block: Uint8Array): Uint8Array;
  decryptBlock(block: Uint8Array): Uint8Array;
}

export interface ModeComponent<Name extends string = string> extends Component<'mode', Name> {
  readonly requiresPadding?: boolean;
  readonly requiredBlockSize?: number;
  readonly aead?: boolean;
  createEncryptor(params: BlockModeTransformParams): Transform;
  createDecryptor(params: BlockModeTransformParams): Transform;
}

export interface BlockModeTransformParams {
  cipher: BlockCipher;
  iv?: Uint8Array;
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

export interface KdfComponent<Name extends string = string> extends Component<'kdf', Name> {
  derive(params: unknown): Uint8Array | Promise<Uint8Array>;
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

export type AnyComponent =
  | CipherComponent
  | ModeComponent
  | PaddingComponent
  | KdfComponent
  | FormatComponent
  | PresetComponent;
