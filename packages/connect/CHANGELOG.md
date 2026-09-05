# @hwlt/era-connect

## 0.7.0

### Minor Changes

- [#20](https://github.com/ERAWLT/era-connect-sdk/pull/20) [`09e1c94`](https://github.com/ERAWLT/era-connect-sdk/commit/09e1c94c257a5d4b68bb9acab3ba1367f9371f2a) Thanks [@gsyabruk](https://github.com/gsyabruk)! - `accounts.btc({ testnet })` now SELECTS a testnet account instead of restyling
  the mainnet one.
  
  **This is a behaviour change, and the behaviour it replaces was wrong.**
  `testnet` only ever chose the address encoding — the bech32 HRP and the
  version byte. The account itself was picked by a coin-type-`0'` predicate, so
  on an export carrying both networks `btc({ testnet: true })` returned the
  MAINNET account rendered under a testnet HRP: a confident wrong answer whose
  path, whose `xfp` (the one a sign request carries) and whose extended key all
  stayed mainnet. On a testnet-only export it returned `undefined`. Both
  behaviours are published — if anything downstream relies on the address
  `btc({ testnet: true })` used to hand back, re-check it before upgrading.
  
  The network is now part of the selection predicate: the match is the export's
  own entry at `m/<purpose>'/<0 | 1>'/…`, both levels **hardened** (a
  `crypto-keypath` can spell a soft level, and `m/84'/1/0'` is a different key,
  not a testnet account), and the answer is `undefined` when there is none.
  There is deliberately no fallback to the other network — a silent fallback is
  the defect being fixed. **Mainnet callers are unaffected:** the old
  predicate's Bitcoin set is exactly purposes 44/49/84/86 at coin type `0'`, so
  every mainnet call selects the entry it always did, and the existing
  BIP-44/49/84 vectors prove it unchanged.
  
  `purpose` is bounded to {44, 49, 84, 86} inside `btc()` itself now, at
  runtime. It used to get that bound as a side effect of classifying the path
  as Bitcoin; moving the network into the predicate lost it, and `BtcPurpose`
  is erased at runtime, so `btc({ purpose: 48 })` — from JavaScript, or through
  a cast — briefly returned a view where it had always returned `undefined`. An
  arbitrary purpose has no script type and no address encoding, so a view over
  it could serve a plausible-looking `xpub()` and refuse only later, at the
  first address. `BtcAccountView.deriveAddress` now also has a default arm that
  throws `invalid-props` (`unsupported BIP purpose <n>`): the switch was
  exhaustive over the four-value union, which meant `tsc` stayed silent while
  the method returned `undefined` from a signature declared `: string` — and
  that reaches a QR encoder or a change output as the text "undefined".
  
  `BtcAccountView`'s constructor no longer takes a `testnet` boolean; the
  network is read off the selected entry's own coin type, and the parameter
  order is now `(entry, purpose, xfp)`. The boolean made it possible to
  reconstruct by hand the exact wrong answer this release removes — a mainnet
  entry wearing a testnet address, path, `xfp` and `tpub` — so the constructor
  goes honest in the same breath as the selector.
  
  **This is a breaking change to a surface that was already published, and it is
  worth being exact about why that is acceptable.** `BtcAccountView` is exported
  from the 0.6.0 root, and `RawAccountEntry` is a plain STRUCTURAL interface: a
  caller does not need the type to be exported by name to build the argument —
  an object literal of the right shape satisfies it, and `new
  BtcAccountView({…}, true, 84, xfp)` compiles against 0.6.0 today. So "the type
  isn't exported, so nobody can be calling this" is **not** the reason, and must
  not be reused as one; in a release where the version bump did not cover the
  change it would be wrong. The reason is the bump itself: this ships as a minor
  on a `0.x` package, which is the breaking level under the range operators npm
  resolves (`^0.6.0` does not admit `0.7.0`), and the break is a compile error
  at the call site — `Expected 3 arguments, but got 4` — not a silent behaviour
  change. A caller who really was passing `testnet: true` beside a mainnet entry
  was getting the confident wrong answer described above; being stopped by the
  compiler is the outcome we want for them.
  
  Extended keys follow the account. On testnet `xpub()` serialises under the
  SLIP-132 testnet version `0x043587cf` (a `tpub…`) and `zpub()` under
  `0x045f1cf6` (a `vpub…` — the SLIP-132 BIP-84 testnet key); mainnet keeps
  `0x0488b21e` / `0x04b24746`. `zpub()` keeps its name and still refuses any
  purpose other than 84. `accountPath`, `receivePath()` and `changePath()` are
  read off the entry's own path, so they follow for free.
  
  What this means in practice: **ERA firmware exports Bitcoin accounts at coin
  type `0'` only**, so for a wallet linked from an ERA device
  `btc({ testnet: true })` is now `undefined` for every purpose. That is the
  truthful answer. The option stays because the export format carries
  coin-type-`1'` accounts and other wallet profiles populate them.
  
  Path classification is deliberately NOT widened: SLIP-44 assigns coin type 1
  to "Testnet (all coins)", so `accounts.keys` still reports `m/84'/1'/0'` as
  `chain: 'unknown'` — it is as much a Litecoin testnet account as a Bitcoin one
  (this package's own `PsbtCoin` admits ltc/doge/dash). `btc({ testnet: true })`
  may resolve that path only because the caller named the chain.
  
  **Exports.** The hand-written allow-list had drifted from what the docs use
  and from what the package's own signatures need. New from the root:
  `randomRequestId`, `uuidStringify`, `bytesToHex`, `hexToBytes`,
  `WALLET_UR_TYPES`, `parseMultiAccountsUr`, `parsePath`, `formatPath`,
  `pathEquals`, `foldRecoveryId`, `splitSignedTronTx`, the CashAddr codec
  (`CASHADDR_PREFIX`, `decodeCashAddr`, `encodeCashAddr`), all ten
  `…AddressFromPublicKey` derivation helpers, and the types `PathLevel`,
  `RawAccountEntry`, `RawMultiAccounts`, `PsbtCoin`, `SignedTronTx`,
  `CashAddrPayload` and `CashAddrType`. Every per-chain subpath now also exports
  the types its own signatures already used — `UrScannerOptions`,
  `ScanFeedResult`, `ScanRejection`, `AnimatedUrOptions`, plus `ExpectedReply`
  on `/xrp` and `PsbtCoin` on `/btc` — and `DEFAULT_ORIGIN`, the value their
  already-exported `EraConnectConfig.origin` defaults to, which was reachable
  only from the root. `/verify` exports every type its own argument objects
  declare: `CardanoWitness` (`VerifyCardanoSignatureArgs.witnesses`),
  `EvmDataType` and `TonDataType` (the `dataType` fields), `TronLatestBlock`
  and `SignedTronTx` (`VerifyTronSignatureArgs.latestBlock` / `.signedTx`),
  `DecodedBchInput` and `DecodedBchOutput` — plus `EraSdkError` and
  `EraErrorCode`, which `parsePsbt`, `decodeBchRawTx` and `bocRootHash` throw
  and which an app importing only `/verify` could not name. Nothing was
  removed.
  
  **`WALLET_UR_TYPES` is now a frozen `readonly string[]`, not a
  `ReadonlySet`.** `ReadonlySet` is erased at compile time, so the export was a
  live `Set` at runtime — and the same object `parseMultiAccountsUr` reads in
  its type gate, which a plain `WALLET_UR_TYPES.add('…')`, no cast required,
  could widen process-wide. The gate keeps its own private `Set` now, built
  once and never handed out. The constant reaches npm for the first time in
  this release, so it is a frozen array from the start and no published code
  can be holding the `Set` shape: `UrScannerOptions.expectedTypes` is a
  `readonly string[]`, so `expectedTypes: WALLET_UR_TYPES` drops straight in,
  with no copy and nothing a caller can widen.
  
  **Docs.** Bitcoin gains an account-selection section covering purpose, network
  and what the ERA export actually carries. The link samples pin
  `expectedTypes: WALLET_UR_TYPES` instead of a hand-written
  `['crypto-multi-accounts']`, which refused every frame of a `crypto-hdkey`
  link (TON's) and looked like a camera fault.
  
  XRP's page no longer says an export carrying the leaf `m/44'/144'/0'/0/0`
  falls outside `accounts.xrp()`. It does not: classification reads the first
  TWO path levels, so such an entry is wrapped as an "account" one level too
  deep — `signingPath` then names `…/0/0/0/0` and `derivePublicKey(0)` is a
  grandchild of the only key the device signs with, with nothing throwing on the
  way and `if (!xrp)` never firing. The page's own opening line is what makes an
  integrator request exactly that path, so it now spells out both shapes, gates
  on `accountPath` instead of on a view merely existing, and reads the pulled
  key straight off the entry. Cosmos's verify snippet no longer invites the
  Ethermint path to be reached by swapping one value in the vanilla block: that
  reply is an `evm-signature`, which carries no public key, and
  `verifyCosmosSignature` reads `publicKey.length` before any guard — so the
  vanilla block's `sig.publicKey!` is a `TypeError` there, in the one place the
  page insists on a verdict. The two paths are separate blocks now, and the
  Ethermint one supplies the account key itself.

## 0.6.0

### Minor Changes

- [`066b76f`](https://github.com/ERAWLT/era-connect-sdk/commit/066b76fe3a2fd46457591eca2c142fa5c0f22fd7) Thanks [@gsyabruk](https://github.com/gsyabruk)! - Close out the external repository audit.
  
  **New:** `accounts.cosmos()` and `accounts.xrp()` — Cosmos and XRP shipped
  full signing modules but no typed account view, and an XRP entry from the
  device classified as `unknown` because `m/44'/144'` was missing from the path
  classifier. Both now behave like every other linked chain; Cosmos addresses
  take the zone's bech32 prefix, XRP exposes the single path the device signs
  with. `SECURITY.md`, issue and pull-request templates, and a dependabot
  configuration are new too.
  
  **Fixed:** the UR type grammar disagreed with itself — a type containing a
  digit could be constructed and then refused as `not-a-ur` on the way back in.
  The protobuf's `sync.proto` still carried Keystone's pre-rename namespace.
  Thirteen lint warnings (six dead imports) are gone, the Biome config no longer
  drifts from the resolved version, and the workspace config no longer both
  forbids and permits the same build script.
  
  **Docs:** the normative protocol spec was four chains behind — Bitcoin message
  signing, the per-chain request-id shape and the QR fragment defaults all
  contradicted the code, and the reference tables omitted seven UR types. The
  spec now states its own scope honestly and the tables cover every type the
  device speaks. The `.proto` schemas are no longer described as proprietary:
  they ship in this package.

## 0.5.3

### Patch Changes

- [`62dc81e`](https://github.com/ERAWLT/era-connect-sdk/commit/62dc81eff0164eb94981e683d05cb83b8373fba1) Thanks [@gsyabruk](https://github.com/gsyabruk)! - `gunzipCapped` now refuses gzip streams with reserved FLG header bits set
  (RFC 1952 requires them to be zero; the underlying inflater silently ignored
  them). No conforming encoder — the device included — ever sets these bits.

## 0.5.2

### Patch Changes

- [`603623f`](https://github.com/ERAWLT/era-connect-sdk/commit/603623f1471d1c007d3d9cd7db103bb5a778215c) Thanks [@gsyabruk](https://github.com/gsyabruk)! - Documentation audit: the package README no longer claims "dedicated modules
  for four chains" (there are eleven) and the Bitcoin message-signing capability is
  described per firmware generation everywhere it is mentioned; the verification
  guide's helper table now lists every exported verifier (TON, Cardano, Sui,
  Cosmos and the mandatory XRP one included); the LTC/DOGE/DASH linking note
  correctly says those entries classify as `unknown` and are found by path.

## 0.5.1

### Patch Changes

- [`0327cce`](https://github.com/ERAWLT/era-connect-sdk/commit/0327ccebd8a4b48981d1f51fe56fe53489078848) Thanks [@gsyabruk](https://github.com/gsyabruk)! - Update the package description and README intro to name the full chain list —
  EVM, Bitcoin (+ Litecoin, Dogecoin, Dash, Bitcoin Cash), Solana, Tron, TON,
  Cardano, Sui, Cosmos and XRP — instead of the original four launch chains.

## 0.5.0

### Minor Changes

- [`2968c27`](https://github.com/ERAWLT/era-connect-sdk/commit/2968c270d8db0ce6f6eefe4765632d5fa6873634) Thanks [@gsyabruk](https://github.com/gsyabruk)! - Add a Bitcoin Cash module (`@hwlt/era-connect/bch`).
  
  BCH cannot ride the PSBT path the rest of the Bitcoin family uses: its
  consensus sighash is BIP-143 with `SIGHASH_FORKID` (0x41), which the device's
  PSBT signer does not apply. It rides the structured `keystone-sign-request`
  envelope instead, so this module takes structured UTXOs and outputs, builds
  the `BchTx` protobuf, and returns the device's complete signed transaction.
  
  - `era.bch.generateSignRequest({ inputs, outputs, fee, xfp })` — CashAddr
    outputs, per-input derivation paths, fee cross-checked against
    `sum(inputs) - sum(outputs)` so the device screen cannot show a fee the
    transaction does not pay.
  - `verifyBchSignedTx` (from `@hwlt/era-connect/verify`) rebuilds the binding
    from the returned transaction: outpoints, output scripts and values, the
    signing key per input, the sighash type, and every signature re-verified
    against a locally recomputed FORKID sighash.
  - CashAddr codec (`decodeCashAddr` / `encodeCashAddr`) and an
    `accounts.bch()` view with local address derivation.
  
  Also: Bitcoin message signing now documents the firmware 2.1.0 behaviour —
  BIP-44/49/84 addresses are signable (Taproot is refused), the source
  fingerprint is mandatory, and the reply may carry the raw 65-byte signature
  instead of base64-as-ASCII. `parseMessageSignature` accepts both forms.

## 0.4.0

### Minor Changes

- [`2db0cb1`](https://github.com/ERAWLT/era-connect-sdk/commit/2db0cb1f5bf8c9748f8506fb8f94d886ae56621a) Thanks [@gsyabruk](https://github.com/gsyabruk)! - Add Sui, Cosmos and XRP modules, and extend the Bitcoin module to
  Litecoin/Dogecoin/Dash via `crypto-psbt-extend`. Sui signs the BLAKE2b
  intent digest (plus the hash-request variant) with local `0x` address
  derivation; Cosmos covers ~35 zones in one module including the
  Ethermint family (keccak digests, `evm-sign-request` wire shape); XRP
  implements the XRP Toolkit `ur:bytes` convention with a mandatory
  signed-binary verifier (canonical STObject walker + SHA-512-half
  signing hash); the Bitcoin-family coins reuse the entire PSBT flow and
  its anti-replay binding.

## 0.3.0

### Minor Changes

- [`6c1e1fd`](https://github.com/ERAWLT/era-connect-sdk/commit/6c1e1fdef238740f31c92faaff5ed3444fccf615) Thanks [@gsyabruk](https://github.com/gsyabruk)! - Add the Cardano module: `cardano-sign-request`/`cardano-signature` with
  UTXO and certificate-key witnesses, witness-set parsing, BLAKE2b-256
  tx-body digest recomputation and BIP32-Ed25519 soft public derivation —
  `verifyCardanoSignature` binds every witness to the linked account's
  soft-derived keys at the request's own signing paths. Linking handles
  Cardano's path-only origin keypaths by resolving against the master
  fingerprint, and `accounts.cardano()` exposes the account key material
  plus `deriveKey(role, index)`.
