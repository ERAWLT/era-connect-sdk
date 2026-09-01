---
"@hwlt/era-connect": minor
---

Add the Cardano module: `cardano-sign-request`/`cardano-signature` with
UTXO and certificate-key witnesses, witness-set parsing, BLAKE2b-256
tx-body digest recomputation and BIP32-Ed25519 soft public derivation —
`verifyCardanoSignature` binds every witness to the linked account's
soft-derived keys at the request's own signing paths. Linking handles
Cardano's path-only origin keypaths by resolving against the master
fingerprint, and `accounts.cardano()` exposes the account key material
plus `deriveKey(role, index)`.
