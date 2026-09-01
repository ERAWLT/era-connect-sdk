# TON

Wire types: `ton-sign-request` (7201) → `ton-signature` (7202).

Three TON-specific facts drive the integration:

- **The device signs a HASH, not the raw bytes.** For a transaction the
  digest is the **root cell's representation hash** of the Bag-of-Cells you
  pass in `signData`; for a TON Connect proof it is
  `sha256(0xFFFF || "ton-connect" || sha256(payload))`. The SDK recomputes
  both in `verifyTonSignature`.
- **One key, two wallet contracts.** V4R2 and V5R1 share the account path
  (`m/44'/607'/0'`); the contract version only changes the ADDRESS. Derive
  the address from `accounts.ton().publicKey` with your TON tooling
  (`@ton/core` etc.) for the contract version your wallet uses.
- **The request id travels as text.** On this chain the ecosystem convention
  is the ASCII bytes of the hyphenated UUID string (tag 37) — the SDK emits
  that form and accepts either form in the echo. You never handle it
  directly.

## 0. Linking

TON is exported as a standalone `crypto-hdkey` (the minimal `{key, keypath,
name}` shape), not inside the multichain export. Scan it like any link QR:

```ts
const scanner = era.scanner({ expectedTypes: ['crypto-hdkey', 'crypto-multi-accounts'] });
// ...feed camera frames...
const accounts = era.parseAccounts(scanner.result());
const ton = accounts.ton()!;
ton.publicKey; // 32-byte Ed25519 — the signer AND the address source
ton.xfp;
```

## 1. Generate the sign request

```ts
import { TonChain } from '@hwlt/era-connect/ton';

const request = era.ton.generateSignRequest({
  signData: bocBytes,                       // Bag-of-Cells of the unsigned message
  dataType: TonChain.DataType.transaction,  // or .tonProof
  path: ton.accountPath,                    // "m/44'/607'/0'"
  xfp: ton.xfp,
  address: bounceableAddress,               // 'UQ…' text — shown on the device
});
```

| Prop | Required | Notes |
|---|---|---|
| `signData` | ✅ | BoC bytes (`@ton/core`: `beginCell()…endCell()` → `Cell.toBoc()`), or the raw proof payload for `tonProof` |
| `dataType` | – | defaults to `transaction` |
| `path`, `xfp` | ✅ | from linking |
| `address` | – | user-friendly bounceable text, display only |

```ts
// @ton/core — external message body for a wallet-contract transfer
const body = wallet.createTransfer({ seqno, messages: [internal({ to, value })] });
const request = era.ton.generateSignRequest({
  signData: body.toBoc({ idx: false }),
  path: ton.accountPath, xfp: ton.xfp, address,
});
```

## 2. Parse the signature

```ts
const scanner = request.scanner();   // create ONCE, feed it the camera frames
const sig = scanner.parse();
sig.signature; // exactly 64 bytes, Ed25519 over the digest above
```

## 3. Verify, assemble & broadcast

```ts
import { verifyTonSignature } from '@hwlt/era-connect/verify';

const check = verifyTonSignature({
  signData: bocBytes,
  dataType: TonChain.DataType.transaction,
  signature: sig.signature,
  publicKey: ton.publicKey,
});
if (!check.ok) throw new Error(check.reason);

// @ton/core: attach the signature and send the external message
const signed = beginCell().storeBuffer(Buffer.from(sig.signature)).storeSlice(bodySlice).endCell();
await client.sendFile(external({ to: walletAddress, body: signed }).toBoc());
```

For a TON Connect proof, return `sig.signature` (base64) in the proof reply —
the dApp verifies it against the wallet's public key.
