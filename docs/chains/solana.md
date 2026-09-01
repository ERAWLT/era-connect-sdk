# Solana

Wire types: `sol-sign-request` (1101) → `sol-signature` (1102).

Two Solana-specific facts drive everything here:

- **Ed25519 has no public child derivation.** The device pre-derives hardened
  accounts (`m/44'/501'/0'…9'`) and exports each as its own entry — the entry
  IS the signer, and its public key (base58) IS the address. Sign requests
  therefore use the **3-level hardened account path**, not a 5-level path.
- **The device signs `signData` verbatim.** No prefix, no transform. That
  makes versioned (v0) transactions work unchanged — and makes it YOUR job to
  pass message bytes, not a serialized signed-tx envelope.

## 1. Generate the sign request

```ts
const sol = accounts.solana()[0];
const request = era.solana.generateSignRequest({
  signData: messageBytes,          // compiled message (see below)
  path: sol.path,                  // "m/44'/501'/0'" — 3 levels, all hardened
  xfp: sol.xfp,
  publicKey: sol.publicKey,        // or address: sol.address
  // signType: SolanaChain.SignType.message  ← off-chain messages only
});
```

`signData` for a transaction is the **compiled message**:

```ts
// @solana/web3.js
const message = new TransactionMessage({ payerKey, recentBlockhash, instructions })
  .compileToV0Message();
const signData = message.serialize();
```

A blockhash is only valid for ~60–90 seconds. Build the message right before
displaying the QR, and if the user takes long on the device, be prepared to
rebuild — but remember a rebuilt message is a NEW request: never mix an old
QR with a new transaction object (verification below is what catches that).

## 2. Parse the signature

```ts
const sig = request.scanner().parse();
sig.signature; // exactly 64 bytes, Ed25519
```

## 3. Verify, assemble & broadcast

```ts
import { verifySolanaSignature } from '@era-wallet/connect/verify';

const check = verifySolanaSignature({
  signData,
  signature: sig.signature,
  publicKey: sol.publicKey,
  broadcastMessageBytes: tx.message.serialize(), // what you are ABOUT to send
});
if (!check.ok) throw new Error(check.reason);

const tx = new VersionedTransaction(message);
tx.addSignature(new PublicKey(sol.address), sig.signature);
await connection.sendRawTransaction(tx.serialize());
```

For off-chain messages returned to a dApp: base58-encode the 64 bytes.
