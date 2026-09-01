# @hwlt/era-connect

## 0.5.2

### Patch Changes

- [`603623f`](https://github.com/ERAWLT/era-connect-sdk/commit/603623f1471d1c007d3d9cd7db103bb5a778215c) Thanks [@gsyabruk](https://github.com/gsyabruk)! - Documentation audit: the package README no longer claims "dedicated modules
  for four chains" (there are ten) and the Bitcoin message-signing capability is
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
