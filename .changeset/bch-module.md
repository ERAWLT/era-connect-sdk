---
'@hwlt/era-connect': minor
---

Add a Bitcoin Cash module (`@hwlt/era-connect/bch`).

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
