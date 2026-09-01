# @hwlt/era-connect

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
