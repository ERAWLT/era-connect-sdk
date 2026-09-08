# @hwlt/era-connect

## 0.8.0

### Minor Changes

- [#22](https://github.com/ERAWLT/era-connect-sdk/pull/22) [`4e8d296`](https://github.com/ERAWLT/era-connect-sdk/commit/4e8d2964f397a835cd8e66fbc75f8cace9afbd66) Thanks [@gsyabruk](https://github.com/gsyabruk)! - Cardano addresses, instead of "use your Cardano library".
  
  `CardanoAccountView.deriveAddress(i, { change })` returns the Shelley BASE
  address, and `cardanoBaseAddress(paymentKey, stakeKey)` is exported for callers
  holding keys of their own. The SDK already soft-derived the keys; only the
  assembly was missing.
  
      header(1) || blake2b224(payment_vkey) || blake2b224(stake_vkey)
  
  Header `0x01` — address type 0, network id 1 — bech32 (not bech32m) under the
  HRP `addr`, exactly as the firmware's `CardanoAddress.cpp` builds it. A base
  address commits to BOTH keys, which is why the function takes two: an address
  built from the payment key alone is an *enterprise* address, a different thing
  that cannot delegate its stake. The stake key is the one at `2/0`.

- [#22](https://github.com/ERAWLT/era-connect-sdk/pull/22) [`e5ec1e0`](https://github.com/ERAWLT/era-connect-sdk/commit/e5ec1e08460f539afda63039af0ebbca977339de) Thanks [@gsyabruk](https://github.com/gsyabruk)! - The whole Cosmos family is addressable, Ethermint included.
  
  `COSMOS_CHAINS` is the registry the firmware's `CosmosCoinInfo` table declares:
  33 zones with their HRP and SLIP-44. Twenty-four of them share coin type 118,
  so the export carries ONE key for all of them and only the HRP differs —
  **enumerate the registry, never the export's entries**, or a caller sees two
  dozen identical rows for the same address.
  
  - `cosmos()` with no argument is unchanged: the shared 118 account.
  - `cosmos('kava')` resolves the entry that zone is actually derived under —
    the six non-118 chains have their own coin types (Secret 529, Cronos 394,
    Kava 459, Terra and Terra Classic 330, THORChain 931).
  - `availableCosmosChains()` lists only the zones a given export can serve.
  - `deriveAddress(i, { chain })` picks the hashing as well as the HRP;
    `{ prefix }` stays the escape hatch for zones the registry does not carry and
    always means the classic recipe.
  
  **Ethermint** (Injective, Evmos, Dymension) are EVM keys wearing a Cosmos coat:
  their account is `m/44'/60'` and the bech32 payload is the ETHEREUM address,
  not `sha256+ripemd160`. `cosmos('injective')` therefore resolves the EVM
  account and encodes with `ethermintAddressFromPublicKey`, which is also
  exported. Encoding one of these with the classic recipe yields a well-formed
  `inj1…` for a different account entirely, so the two recipes are separate
  functions rather than a flag.

- [#22](https://github.com/ERAWLT/era-connect-sdk/pull/22) [`ea23894`](https://github.com/ERAWLT/era-connect-sdk/commit/ea23894652387a8f5b30fa1e3accb0a1ecaa6a8a) Thanks [@gsyabruk](https://github.com/gsyabruk)! - The two Ledger EVM schemes are visible.
  
  The device exports three EVM derivations and `evm()` answers only the standard
  one, so the other two were in the export and unreachable. They are not
  interchangeable with it, or with each other:
  
  - `evmLedgerLive()` — ten fully derived LEAVES at `m/44'/60'/<n>'/0/0`, one key
    per account with nothing to derive further. Asking such a view for index 1
    throws rather than deriving below a leaf.
  - `evmLedgerLegacy()` — an account whose addresses sit ONE level below it,
    `m/44'/60'/0'/<index>`, not two. Deriving it like the standard account gives
    a different address.
  
  Ledger Live leaves and the Ethermint keys share a path shape; the chain code is
  what separates them, and only the former are returned here.
  
  `derivePublicKeyChild` is exported for the single-step case.

- [#22](https://github.com/ERAWLT/era-connect-sdk/pull/22) [`21c584b`](https://github.com/ERAWLT/era-connect-sdk/commit/21c584bb68b30b173c57107f9a02cc31ac0a4098) Thanks [@gsyabruk](https://github.com/gsyabruk)! - `solana()` entries now say which derivation scheme they belong to.
  
  The device ships all three Solana derivations, and the firmware tells them
  apart by PATH DEPTH alone — all three carry the same `Derivation::Solana`.
  `index` reads the third path level, so before this three different accounts all
  reported index 0 with three different addresses, and two reported each of 1..4.
  
  - `view.scheme` is `single` (`m/44'/501'`), `account` (`m/44'/501'/<n>'`) or
    `sub-account` (`m/44'/501'/<n>'/0'`).
  - `solana({ scheme })` filters, which is what a wallet showing one account list
    actually wants.
  - `index` is documented as unique only WITHIN a scheme.
  
  Additive: an unfiltered `solana()` still returns every key the export shipped.

- [#22](https://github.com/ERAWLT/era-connect-sdk/pull/22) [`7599f71`](https://github.com/ERAWLT/era-connect-sdk/commit/7599f71f8eb4badc23f7448adb6d0339ab78e559) Thanks [@gsyabruk](https://github.com/gsyabruk)! - `accounts.btc({ purpose: 86 }).deriveAddress()` now returns a taproot address
  instead of throwing.
  
  **This is a behaviour change, and the behaviour it replaces was actively
  harmful.** The SDK used to refuse purpose 86 and tell the caller to derive it
  "from `xpub()` with your Bitcoin library". A consumer did exactly that, omitted
  the BIP-341 tweak, and shipped a Receive screen offering a `bc1p…` built from
  the untweaked internal key — a valid address that no BIP-86 signer, the ERA
  device included, can key-path spend.
  
  The witness program is the tweaked output key, never the BIP-32 child key:
  
  ```
  P = lift_x(x(child))            // BIP-340 lift: always the even-Y point
  t = int(taggedHash("TapTweak", x(P)))
  Q = P + t*G
  program = x(Q)                  // bech32m, witness version 1
  ```
  
  `btcTaprootAddressFromPublicKey(publicKey33, hrp)` is exported for callers who
  hold a key rather than an account view. No new dependency: `@noble/curves`
  already exposes `lift_x` and the tagged hash, and `@scure/base` already exports
  `bech32m`.
  
  If you were catching `invalid-props` from `deriveAddress()` on a purpose-86
  view as a supported control-flow path, that catch is now dead code.

- [#22](https://github.com/ERAWLT/era-connect-sdk/pull/22) [`2a3ee5b`](https://github.com/ERAWLT/era-connect-sdk/commit/2a3ee5bb77af658857938e084a446fc03c251bd4) Thanks [@gsyabruk](https://github.com/gsyabruk)! - TON addresses, instead of "use your TON library".
  
  `TonAccountView.address` is the V4R2 wallet address (`UQ…`, non-bounceable —
  the form a wallet shows for receiving), `.bounceableAddress` the `EQ…` form,
  and `tonAddressFromPublicKey(key)` is exported.
  
  A TON address is not a hash of the key: it is the hash of the wallet CONTRACT
  the key would deploy. `StateInit{code, data}` is a cell with two refs, its
  representation hash is the account id, and the friendly form is
  `tag || workchain || account_id || crc16` in base64url. The code cell never
  varies, so only its hash and depth are carried — the same two constants the
  firmware uses, not a whole embedded BOC.
  
  The test vector is the firmware's own device-verified regression case, and the
  public key it uses was derived independently rather than by this package.

- [#22](https://github.com/ERAWLT/era-connect-sdk/pull/22) [`7dc784e`](https://github.com/ERAWLT/era-connect-sdk/commit/7dc784e36fd0b16310f827272e3565bfcdc82df6) Thanks [@gsyabruk](https://github.com/gsyabruk)! - Litecoin, Dogecoin and Dash are now named and addressable, and `evm()` no
  longer answers with a leaf.
  
  **Altcoins.** The SDK signed PSBTs for these three (`PsbtCoin.ltc`, `.doge`,
  `.dash`) long before it could name an address for them: `classify` returned
  `unknown` and there was no view, so a caller holding a perfectly good Litecoin
  account had no way to ask where to receive. They are now classified at their
  own mainnet coin types — 2', 3', 5' — and `wallet.litecoin()`,
  `.dogecoin()`, `.dash()` return a `UtxoAccountView`.
  
  The encoding is the machinery Bitcoin already uses under different version
  bytes, taken from each coin's `CoinInfo` in the firmware: LTC 48/50 (`L…`,
  `M…`, `ltc1q…`), DOGE 30/22 (`D…`), DASH 76/16 (`X…`).
  `p2pkhAddressFromPublicKey` and `nestedSegwitAddressFromPublicKey` take the
  version byte explicitly and are exported; the Bitcoin-specific helpers now
  delegate to them and keep their signatures.
  
  **`evm()` guard.** `classify` reads only the first two path levels, and three
  different things start `m/44'/60'`: the account, the Ledger Live leaves
  `m/44'/60'/<n>'/0/0`, and the Ethermint keys Injective / Evmos / Dymension are
  exported under. `evm()` took the first entry that classified as evm, so it
  could hand back a leaf — and a view over a leaf reports the leaf as its account
  path and derives two levels below it, answering a real key at a nonsense path.
  It now requires an account-shaped entry (depth 3).

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
