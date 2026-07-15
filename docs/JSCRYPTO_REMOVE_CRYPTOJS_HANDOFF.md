# jscrypto: Remove crypto-js Dependency Handoff

## Goal

Remove the runtime dependency on `crypto-js` from `repos/jscrypto`, while preserving the supported cipher/mode/padding/KDF/format API and CryptoJS-compatible outputs where compatibility is intentionally part of the package.

Important public API clarification:

- Keep the supported crypto component API: ciphers, modes, paddings, KDFs, formats, registry, cipher facade, passphrase facade, streaming transforms, and browser bundles.
- Intentionally remove the CryptoJS adapter public API. This includes `CryptoJS`, `bytesToWordArray`, `wordArrayToBytes`, `bytesToWords`, `wordsToBytes`, and `createCryptoJsBlockCipher`.
- Update tests that directly exercise the adapter, especially `tests/coverage-edges.test.mjs`. Those tests currently exist for coverage of the adapter, not because the adapter should remain public forever.

This is a migration project, not a redesign project. The first successful result should be boring:

- `@jscrypto/classic` no longer depends on `crypto-js`.
- `@types/crypto-js` is no longer needed.
- `packages/classic/src/adapter/crypto-js.ts` is removed or replaced by non-exported test-only compatibility code.
- Existing tests pass.
- Coverage remains 100%.
- The main classic browser bundle remains usable without bundled hash implementations.
- KDF/passphrase flows remain compatible after callers opt in to hash registration through `registry.useHash(...)` or `registerClassicHashes(registry)`.

## Repository

Work in:

```text
repos/jscrypto
```

Important package files:

```text
package.json
packages/classic/package.json
packages/classic/src/index.ts
packages/classic/src/adapter/crypto-js.ts
packages/classic/src/ciphers/aes.ts
packages/classic/src/ciphers/des.ts
packages/classic/src/ciphers/triple-des.ts
packages/classic/src/ciphers/rc4.ts
packages/classic/src/kdfs/evpkdf.ts
packages/classic/src/kdfs/pbkdf2.ts
packages/classic/src/formats/openssl.ts
packages/classic/src/modes/*.ts
packages/classic/src/paddings/*.ts
tests/*.test.mjs
```

## Current State

Already native:

- Core registry/facade/transform APIs.
- Block modes: CBC, CFB, CTR, OFB, ECB.
- AES-GCM mode, including AAD and tag handling.
- Paddings: NoPadding, Pkcs7, AnsiX923, Iso10126, Iso97971, ZeroPadding.
- OpenSSL `Salted__` format parser/stringifier.
- RC4 / RC4Drop.

Still depends on `crypto-js`:

- AES block cipher.
- DES block cipher.
- TripleDES block cipher.
- EvpKDF.
- PBKDF2.
- Public exports from `packages/classic/src/adapter/crypto-js.ts`.

Dependency locations:

```text
packages/classic/package.json
  dependencies.crypto-js

package.json
  devDependencies.@types/crypto-js

packages/classic/src/adapter/crypto-js.ts
  imports CryptoJS from crypto-js

packages/classic/src/index.ts
  exports ./adapter/crypto-js.js
```

## Non-Goals

Do not:

- Change public names such as `AES`, `DES`, `TripleDES`, `CBC`, `Pkcs7`, `EvpKDF`, `PBKDF2`, `OpenSSL`.
- Assume the CryptoJS adapter export must be preserved. Removing that adapter is part of this task.
- Change current error messages unless tests are explicitly updated for a better message. The hash lookup error is an allowed exception: missing registered hashes should consistently throw `Hash not registered: <name>.`.
- Add Web Crypto as a backend. Web Crypto is async and does not cover the classic API shape cleanly.
- Add a new runtime dependency just to replace `crypto-js`, unless the owner explicitly approves it.
- Remove DES/TripleDES/RC4 just because they are old. They are required for classic compatibility.
- Rework the package split. Keep `@jscrypto/core` and `@jscrypto/classic`.
- Modify external consumers such as online-tools. This handoff is scoped to the jscrypto package only. Document the consumer integration contract, but do not require online-tools file changes or e2e runs for completion.

## Compatibility Requirements

The migration must preserve:

- AES-128/192/256 block encryption/decryption.
- DES with 8-byte keys.
- TripleDES with 16-byte and 24-byte keys.
- CBC/CFB/CTR/OFB/ECB output for the same key, IV, padding, and plaintext.
- AES-GCM output and tag verification.
- RC4 and RC4Drop behavior.
- EvpKDF output compatible with CryptoJS/OpenSSL passphrase encryption.
- PBKDF2 output compatible with current tests, including CryptoJS 4.x default hash behavior.
- KDF hash selection through `registry.useHash(...)`, without bundling hash implementations into the main `@jscrypto/classic` browser bundle.
- OpenSSL salted output:

```text
Salted__ || 8-byte salt || ciphertext
```

Pay special attention to passphrase flows. They combine KDF, salt handling, key/IV split, mode, padding, and format. They are likely to catch subtle migration regressions.

## Recommended Strategy

Use a staged migration. Do not remove `crypto-js` first.

The safest sequence is:

1. Strengthen golden-vector coverage while `crypto-js` is still present.
2. Replace AES block cipher.
3. Replace DES block cipher.
4. Replace TripleDES block cipher.
5. Add hash registry support and an opt-in classic hashes entry/bundle.
6. Replace EvpKDF so it resolves hashes from the registry.
7. Replace PBKDF2 so it resolves hashes from the registry.
8. Remove `adapter/crypto-js.ts` and package dependencies.
9. Rebuild browser bundles and validate the package-level consumer integration contract.

Each stage should leave the repo green.

## Stage 0: Baseline and Golden Vectors

Before replacing anything, run:

```sh
npm test
npm run coverage
npm run build
```

Add or verify golden vectors for:

- AES block-level known-answer tests for 128/192/256-bit keys.
- DES block-level known-answer tests.
- TripleDES block-level known-answer tests, including 2-key and 3-key variants.
- AES-CBC with Pkcs7.
- AES-CBC with NoPadding.
- AES ECB with Pkcs7.
- AES CFB/CTR/OFB.
- DES and TripleDES modes currently covered by the compatibility test suite.
- EvpKDF with the full supported hash set. At minimum, include golden vectors for default MD5 plus every hash name that remains accepted through `registerClassicHashes(registry)`.
- PBKDF2 with the full supported hash set. At minimum, include golden vectors for default SHA256 plus every hash name that remains accepted through `registerClassicHashes(registry)`.
- Passphrase cipher with fixed salt and OpenSSL format.
- Negative KDF/passphrase tests where no hash has been registered yet.

Existing tests already cover much of this. Extend only where the migration needs stronger lock-in.

Keep compatibility tests as permanent tests. If a test name says `matches CryptoJS`, it can continue to mean "matches previously captured CryptoJS-compatible vectors" after the dependency is removed.

## Stage 1: Native AES Block Cipher

Replace:

```text
packages/classic/src/ciphers/aes.ts
```

Current implementation delegates block encryption to `createCryptoJsBlockCipher`.

Target implementation:

- Implement AES key expansion.
- Implement single-block encrypt/decrypt for 16-byte blocks.
- Keep `createAesCipher(key): BlockCipher`.
- Keep validation:

```text
AES key must be 128, 192, or 256 bits.
```

Important:

- Modes already exist outside AES. AES only needs `encryptBlock()` and `decryptBlock()`.
- GCM also uses the AES block cipher. Re-run AES-GCM tests after replacing AES.
- Avoid BigInt so ES2015 browser builds remain straightforward.

Suggested internal files:

```text
packages/classic/src/ciphers/aes.ts
packages/classic/src/ciphers/aes-tables.ts
```

Done when:

```sh
npm test
npm run coverage
npm run build
```

pass and `aes.ts` no longer imports `../adapter/crypto-js.js`.

## Stage 2: Native DES Block Cipher

Replace:

```text
packages/classic/src/ciphers/des.ts
```

Target implementation:

- Implement DES key schedule.
- Implement single-block encrypt/decrypt for 8-byte blocks.
- Preserve odd/parity-bit behavior as currently observed. The current API accepts 8 bytes and treats them as 64 input bits. Do not silently reject keys because parity bits are invalid unless existing behavior already does that.
- Keep validation:

```text
DES key must be 64 bits.
```

Suggested internal files:

```text
packages/classic/src/ciphers/des.ts
packages/classic/src/ciphers/des-tables.ts
```

Done when DES tests and full suite pass, and `des.ts` no longer imports `../adapter/crypto-js.js`.

## Stage 3: Native TripleDES

Replace:

```text
packages/classic/src/ciphers/triple-des.ts
```

Target implementation:

- Build TripleDES from the native DES block primitive.
- Support 16-byte keys as K1, K2, K1.
- Support 24-byte keys as K1, K2, K3.
- Encrypt with EDE: encrypt K1, decrypt K2, encrypt K3.
- Decrypt with DED: decrypt K3, encrypt K2, decrypt K1.
- Keep validation:

```text
Triple DES key must be 128 or 192 bits.
```

Done when TripleDES tests and full suite pass, and `triple-des.ts` no longer imports `../adapter/crypto-js.js`.

## Stage 4: Hash Registry and Opt-In Hash Bundle

KDFs currently call CryptoJS hashers through:

```text
packages/classic/src/kdfs/evpkdf.ts
packages/classic/src/kdfs/pbkdf2.ts
```

Replace that implicit CryptoJS lookup with explicit hash registration.

This decision intentionally supersedes the earlier architecture note that said there would be no global hash/MAC registry in the first version. Update `docs/architecture.md` and `docs/current-online-tools-scope.md` in this migration.

Core/classic should support:

```ts
registry.useHash(hashComponent)
registry.getHash(name)
```

This requires extending the core component model:

```ts
export type ComponentKind = 'cipher' | 'mode' | 'padding' | 'kdf' | 'format' | 'preset' | 'hash';

export interface KdfDeriveContext {
  getHash(name: string): HashComponent;
}

export interface KdfComponent<Name extends string = string> extends Component<'kdf', Name> {
  derive(params: unknown, context: KdfDeriveContext): Uint8Array | Promise<Uint8Array>;
}
```

`Registry` should implement `useHash()` and `getHash()` as conveniences over the component registry. Registration and lookup must both normalize names, so registering a component named `SHA-256` and looking up `SHA256` works.

KDF wiring is fixed as follows:

- `passphrase.ts` / registry-level passphrase flows call `kdf.derive(params, context)`.
- The KDF component receives a context with `getHash(name)`.
- The KDF component resolves `params.hash ?? defaultHashName` through `context.getHash(...)`.
- The typed direct helpers `deriveEvpKdf(...)` and `derivePbkdf2(...)` do not access the registry. They must receive a concrete `HashComponent` in their params.
- Tests that directly call `deriveEvpKdf(...)` or `derivePbkdf2(...)` must import/register hash components from the opt-in hashes entry and pass the concrete hash component.

Example direct helper shape:

```ts
derivePbkdf2({
  passphrase,
  salt,
  iterations,
  length,
  hash: sha256,
});
```

Example component shape:

```ts
pbkdf2.derive({
  passphrase,
  salt,
  iterations,
  length,
  hash: 'SHA256',
}, {
  getHash: registry.getHash,
});
```

Hash implementations must not be imported by the main `@jscrypto/classic` entry or main browser bundle. `PBKDF2` and `EvpKDF` should contain KDF logic only; they should resolve hash algorithms from the registry at runtime.

Recommended hash component shape:

```ts
interface HashComponent<Name extends string = string> {
  readonly kind: 'hash';
  readonly name: Name;
  readonly blockSize: number;
  readonly digestSize: number;
  hash(input: Uint8Array): Uint8Array;
}
```

PBKDF2 needs `blockSize` for HMAC. EvpKDF only needs `hash(input)`, but it should use the same component interface.

Name lookup should normalize common spelling differences. For example, `sha-256`, `SHA256`, and `sha256` should resolve to the same registered component.

Missing hashes must fail clearly. This applies both to unsupported names and to supported default names that were not registered:

```text
Hash not registered: SHA256.
Hash not registered: MD5.
```

Default hash names:

- EvpKDF default hash name is `MD5`.
- PBKDF2 default hash name is `SHA256` for CryptoJS 4.x compatibility.

These defaults are names only. They do not imply that `@jscrypto/classic` bundles MD5 or SHA256.

### Opt-In Classic Hashes Entry

Provide an optional convenience entry that registers common CryptoJS-compatible hashes, but keep it out of the main classic bundle.

Preferred package shape:

```ts
import { registry } from '@jscrypto/classic';
import { registerClassicHashes } from '@jscrypto/classic/hashes';

registerClassicHashes(registry);
```

Preferred browser bundle shape:

```html
<script src="jscrypto-classic.iife.min.js"></script>
<script src="jscrypto-classic-hashes.iife.min.js"></script>
<script>
  jscryptoClassicHashes.registerClassicHashes(jscryptoClassic.registry);
</script>
```

The main bundle:

```text
jscrypto-classic.iife.min.js
```

must not include MD5/SHA implementations merely because KDFs exist.

The optional bundle:

```text
jscrypto-classic-hashes.iife.min.js
```

may include MD5/SHA implementations and `registerClassicHashes(registry)`.

Important entry-graph rule: generic HMAC is KDF infrastructure, not a concrete hash implementation. Put HMAC in a main-entry-accessible path such as `packages/classic/src/kdfs/hmac.ts` or `packages/classic/src/mac/hmac.ts`, because PBKDF2 in the main bundle needs HMAC logic. Keep `packages/classic/src/hashes/` limited to concrete hash implementations and `registerClassicHashes(registry)`.

Hash support policy is fixed for this migration: keep the full CryptoJS-compatible hash set in the opt-in hashes entry and add golden vectors for each accepted hash.

The opt-in hashes entry must support at least:

```text
MD5
SHA1
SHA224
SHA256
SHA384
SHA512
SHA3
RIPEMD160
```

Do not silently support only MD5/SHA1/SHA256/SHA512 while leaving docs or tests implying CryptoJS-compatible dynamic hash selection.

SHA3 compatibility detail: CryptoJS SHA3 defaults to 512-bit output. The `SHA3` component registered by `registerClassicHashes(registry)` must use the CryptoJS-compatible 512-bit digest unless a separate explicit SHA3 variant API is designed and documented.

Suggested files:

```text
packages/core/src/component.ts
packages/core/src/registry.ts
packages/classic/src/hashes/md5.ts
packages/classic/src/hashes/sha1.ts
packages/classic/src/hashes/sha224.ts
packages/classic/src/hashes/sha256.ts
packages/classic/src/hashes/sha384.ts
packages/classic/src/hashes/sha512.ts
packages/classic/src/hashes/sha3.ts
packages/classic/src/hashes/ripemd160.ts
packages/classic/src/hashes/index.ts
packages/classic/src/hashes/register.ts
packages/classic/src/hashes-entry.ts
packages/classic/src/kdfs/hmac.ts
scripts/build.mjs
```

The exact entry filename can differ, but the build must expose a subpath such as `@jscrypto/classic/hashes` and a separate browser bundle for the opt-in hash set.

String passphrases must match current CryptoJS-compatible behavior. CryptoJS parses JavaScript strings as UTF-8 for these paths; preserve UTF-8 string encoding.

KDF length compatibility is subtle. Current KDF code passes:

```ts
keySize: params.length / 4
```

to CryptoJS, where `keySize` is in 32-bit words. Native implementations must preserve the resulting byte-length behavior, including non-4-byte-aligned lengths such as 15 bytes, unless the owner explicitly chooses to add stricter validation and update tests/docs. Add coverage for at least one non-4-byte-aligned KDF length before replacing CryptoJS.

## Stage 5: Native EvpKDF

Replace:

```text
packages/classic/src/kdfs/evpkdf.ts
```

EvpKDF must not import MD5 directly from the main classic entry. The component should resolve `params.hash ?? 'MD5'` through `context.getHash(...)`. The typed direct helper `deriveEvpKdf(...)` should require `hash: HashComponent` in its params and must not accept a string hash name.

CryptoJS-compatible EvpKDF behavior:

```text
D_0 = empty
derived = empty
while derived.length < requested length:
  block_input = D_(i-1) || password || salt
  D_i = HASH(block_input)
  repeat (iterations - 1) times:
    D_i = HASH(D_i)
  derived = derived || D_i
return first requested length bytes of derived
```

Defaults:

- Default hash name must remain `MD5`.
- Default iterations should remain 1.

Preserve:

- `passphrase: Uint8Array | string`
- `salt: Uint8Array | string`
- `iterations?: number`
- `length: number`
- Component params: `hash?: string`
- Direct helper params: `hash: HashComponent`

Preserve validation:

```text
EvpKDF length must be a positive integer.
EvpKDF iterations must be a positive integer.
Hash not registered: ...
```

Done when `evpkdf.ts` no longer imports `../adapter/crypto-js.js`, direct helper tests pass with explicit hash components, and component/passphrase tests pass after registering hashes with the registry.

## Stage 6: Native PBKDF2

Replace:

```text
packages/classic/src/kdfs/pbkdf2.ts
```

PBKDF2 must not import SHA256 or other concrete hash implementations from the main classic entry. HMAC itself should live outside `packages/classic/src/hashes/` so PBKDF2 can use it without pulling the opt-in hash implementations into the main bundle. The component should resolve `params.hash ?? 'SHA256'` through `context.getHash(...)`, then perform HMAC using the registered hash component's `blockSize` and `hash()` method. The typed direct helper `derivePbkdf2(...)` should require `hash: HashComponent` in its params and must not accept a string hash name.

Implement PBKDF2-HMAC per standard behavior:

```text
T_i = F(password, salt, iterations, i)
DK = T_1 || T_2 || ...
```

Defaults and hash name handling must match current tests and API.

CryptoJS 4.x default PBKDF2 hash name is `SHA256`. Preserve that default. Do not default to SHA1. The default name does not mean SHA256 is bundled into the main classic entry.

Preserve validation:

```text
PBKDF2 iterations must be a positive integer.
PBKDF2 length must be a positive integer.
Hash not registered: ...
```

Done when `pbkdf2.ts` no longer imports `../adapter/crypto-js.js`, direct helper tests pass with explicit hash components, and component/passphrase tests pass after registering hashes with the registry.

## Stage 7: Remove crypto-js Adapter and Dependency

Only do this after all imports are gone.

This stage intentionally removes a previously exported adapter API. This is allowed for this migration. The supported public surface after this stage is the jscrypto cipher/mode/padding/KDF/format API, not the CryptoJS adapter API.

Remove:

```text
packages/classic/src/adapter/crypto-js.ts
```

Update:

```text
packages/classic/src/index.ts
```

Remove:

```ts
export * from './adapter/crypto-js.js';
```

Update package files:

```text
packages/classic/package.json
  remove dependencies.crypto-js
  remove crypto-js keyword if desired

package.json
  remove devDependencies.@types/crypto-js
```

Update tests:

```text
tests/coverage-edges.test.mjs
```

Remove or rewrite coverage tests for:

```text
CryptoJS
bytesToWordArray
wordArrayToBytes
bytesToWords
wordsToBytes
createCryptoJsBlockCipher
```

Update docs that describe the current adapter:

```text
docs/architecture.md
docs/current-online-tools-scope.md
README.md
CHANGELOG.md
```

Then run:

```sh
npm install
npm test
npm run coverage
npm run build
npm pack --workspaces --dry-run
```

Confirm generated browser bundles do not include `crypto-js`.

## Stage 8: Package Bundle and Consumer Contract Check

This handoff is scoped to `repos/jscrypto`. Do not modify external consumers in this task.

The package must expose a clear consumer contract:

- Consumers that do not use KDF/passphrase flows can load only the main classic bundle.
- Consumers that use `EvpKDF`, `PBKDF2`, or passphrase cipher flows must register compatible hashes first.
- Consumers can register their own hash components via `registry.useHash(...)`.
- Consumers can opt into built-in compatibility hashes by importing `@jscrypto/classic/hashes` or loading `jscrypto-classic-hashes.iife.min.js`, then calling `registerClassicHashes(registry)`.

Browser bundle contract:

```html
<script src="jscrypto-classic.iife.min.js"></script>
<!-- Required only for built-in KDF hash implementations. -->
<script src="jscrypto-classic-hashes.iife.min.js"></script>
<script>
  jscryptoClassicHashes.registerClassicHashes(jscryptoClassic.registry);
</script>
```

Package tests must cover this contract without depending on online-tools:

- Main classic registry does not contain hashes by default.
- `classicPreset()` does not include hash components.
- `registry.createPassphraseCipher(...)` fails clearly if the required default hash is not registered.
- After `registerClassicHashes(registry)`, EvpKDF/PBKDF2 passphrase flows work.
- A custom hash component registered with `registry.useHash(...)` can be selected by KDF name lookup.

## Implementation Notes

### Byte Semantics

Use `Uint8Array` everywhere internally.

Avoid:

- WordArray-style public APIs.
- BigInt in browser-facing code.
- Mutating caller-provided inputs unless the existing API explicitly allows it.

### Constant-Time Checks

Authentication/tag verification should remain constant-time where applicable. AES-GCM already has tag comparison behavior; do not regress it.

### Padding

Padding code is already native. Do not rewrite it unless a cipher migration exposes a specific issue.

### Modes

Modes are already native and should not be rewritten as part of dependency removal.

Re-run mode tests after AES/DES/TripleDES replacement because modes depend on block cipher correctness.

### RC4

RC4 is already native. Do not migrate it.

Only touch RC4 if tests reveal a regression caused by broader refactoring.

### Licensing

Do not paste large portions of CryptoJS source into the repository as the main migration strategy.

Acceptable:

- Use standards and public test vectors.
- Use the current CryptoJS-backed implementation to generate permanent golden vectors before removing the dependency.
- Reimplement algorithms in this repository's style.

If any third-party code is copied, preserve its license and make that choice explicit in the PR description. Prefer not to copy.

## Suggested Task Breakdown for Sub-Agents

If multiple AIs/agents will work in parallel, split the work like this:

### Agent A: AES

Scope:

- Implement native AES.
- Add block-level AES vectors.
- Keep GCM passing.

Files:

```text
packages/classic/src/ciphers/aes.ts
packages/classic/src/ciphers/aes-tables.ts
tests/aes-*.test.mjs
```

### Agent B: DES and TripleDES

Scope:

- Implement native DES.
- Implement TripleDES using native DES.
- Add DES/TripleDES block-level vectors.

Files:

```text
packages/classic/src/ciphers/des.ts
packages/classic/src/ciphers/des-tables.ts
packages/classic/src/ciphers/triple-des.ts
tests/des-compat.test.mjs
tests/triple-des-compat.test.mjs
```

### Agent C: Hash Registry, Opt-In Hashes, and KDFs

Scope:

- Add `registry.useHash(...)` and hash lookup support.
- Define the hash component interface.
- Implement optional MD5/SHA/RIPEMD160/SHA3 concrete hash primitives for the opt-in hashes entry.
- Keep generic HMAC outside `packages/classic/src/hashes/`, for example in `packages/classic/src/kdfs/hmac.ts`, so the main KDF entry can use HMAC without importing concrete hash implementations.
- Add `registerClassicHashes(registry)`.
- Add a separate `@jscrypto/classic/hashes` subpath and separate browser bundle.
- Replace EvpKDF so it resolves hashes from the registry.
- Replace PBKDF2 so it resolves hashes from the registry.
- Ensure main `@jscrypto/classic` does not import or bundle hash implementations.
- Update coverage configuration and tests so the opt-in hashes subpath is tested and counted toward the 100% thresholds.

Files:

```text
packages/core/src/component.ts
packages/core/src/registry.ts
packages/core/src/passphrase.ts
packages/classic/src/hashes/*.ts
packages/classic/src/hashes-entry.ts
packages/classic/src/kdfs/hmac.ts
packages/classic/src/kdfs/evpkdf.ts
packages/classic/src/kdfs/pbkdf2.ts
package.json
packages/classic/package.json
scripts/build.mjs
tests/kdf-compat.test.mjs
tests/passphrase-cipher.test.mjs
```

### Agent D: Cleanup and Packaging

This is a serial gate. Do not run this cleanup before Agent A, Agent B, and Agent C have removed all source imports of `../adapter/crypto-js.js` and the full test suite is green.

Scope:

- Remove adapter export.
- Remove package dependencies.
- Verify package tarballs.
- Verify browser bundles, including that hashes are split from the main classic bundle.
- Update README/CHANGELOG/docs.
- Update adapter-specific tests.

Files:

```text
package.json
package-lock.json
packages/classic/package.json
packages/classic/src/index.ts
README.md
CHANGELOG.md
docs/architecture.md
docs/current-online-tools-scope.md
tests/coverage-edges.test.mjs
```

## Final Acceptance Criteria

The task is complete when all are true:

- `rg "crypto-js" repos/jscrypto/packages repos/jscrypto/package.json repos/jscrypto/package-lock.json` finds no runtime dependency or source import.
- `rg "from 'crypto-js'|from \"crypto-js\"|adapter/crypto-js|CryptoJS" packages tests package.json packages/classic/package.json` finds no source import, runtime dependency, or stale adapter test in `repos/jscrypto`.
- Documentation may mention CryptoJS only historically, for example in CHANGELOG notes saying the dependency was removed. Do not use broad `rg "crypto-js" .` as the sole acceptance check.
- `@types/crypto-js` is removed.
- `packages/classic/src/adapter/crypto-js.ts` is removed.
- `packages/classic/src/index.ts` no longer exports the adapter.
- `tests/coverage-edges.test.mjs` no longer tests WordArray adapter helpers.
- `npm test` passes in `repos/jscrypto`.
- `npm run coverage` passes in `repos/jscrypto` with 100% thresholds.
- Coverage includes the opt-in hashes entry/subpath. If the coverage command currently includes only `packages/core/dist/index.mjs` and `packages/classic/dist/index.mjs`, update it or add tests that import the hashes subpath so hash implementations are measured.
- `npm run build` passes in `repos/jscrypto`.
- Browser bundles build successfully.
- Build metadata or an equivalent entry-graph inspection shows that `jscrypto-classic.iife.min.js` does not import files under `packages/classic/src/hashes/`.
- Optional hash registration is available through a subpath and separate browser bundle, for example `@jscrypto/classic/hashes` and `jscrypto-classic-hashes.iife.min.js`.
- KDFs work when the required hashes are registered through `registry.useHash(...)`.
- KDFs fail clearly when the required hash is not registered.
- `classicPreset()` and the default exported classic `registry` do not include hash components until `registerClassicHashes(registry)` or explicit `registry.useHash(...)` calls are made.
- README/CHANGELOG/docs mention that `@jscrypto/classic` no longer depends on CryptoJS and that the old CryptoJS adapter export was removed.

## Useful Commands

From `repos/jscrypto`:

```sh
npm test
npm run coverage
npm run build
npm pack --workspaces --dry-run
rg "from 'crypto-js'|from \"crypto-js\"|adapter/crypto-js|CryptoJS" packages tests package.json packages/classic/package.json
```

If the build script can emit esbuild metafiles, inspect the metafile for `jscrypto-classic.iife.min.js` and confirm it does not include `packages/classic/src/hashes/*`. Do not use simple string scans for `MD5` or `SHA256` as the acceptance check; the main bundle may legitimately contain default hash names or error messages without containing hash implementations.
