# @hwlt/era-connect

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
