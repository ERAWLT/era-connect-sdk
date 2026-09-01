# Sui

Wire types: `sui-sign-request` (7101) / `sui-sign-hash-request` (7103) →
`sui-signature` (7102).

- **`intentMessage` is the whole signing payload** — intent prefix + BCS
  transaction bytes, exactly as your Sui tooling emits it. The device signs
  BLAKE2b-256 of those bytes (`suiIntentDigest`).
- **Paths are fully hardened** (SLIP-10 Ed25519, `m/44'/784'/0'/0'/0'`);
  each exported entry IS a signer, like Solana.
- The reply carries the signer's public key; `accounts.sui()[i].address`
  derives the `0x…` address locally (BLAKE2b-256 of `0x00 || publicKey`).

```ts
// 1 · request
const sui = accounts.sui()[0]!;
const request = era.sui.generateSignRequest({
  intentMessage,               // @mysten/sui: messageWithIntent(...)
  path: sui.path,
  xfp: sui.xfp,
  address: sui.address,
});
// (or generateSignHashRequest({ messageHash }) to sign a 32-byte digest directly)

// 2 · reply
const scanner = request.scanner();   // create ONCE, feed camera frames
const sig = scanner.parse();         // { signature, publicKey }

// 3 · verify + submit
import { verifySuiSignature } from '@hwlt/era-connect/verify';
const check = verifySuiSignature({
  intentMessage,
  signature: sig.signature,
  publicKey: sig.publicKey,
  expectedPublicKey: sui.publicKey,  // binds the reply to YOUR wallet
});
if (!check.ok) throw new Error(check.reason);
// serialized signature for the network: flag 0x00 || sig || pubkey (base64)
```
