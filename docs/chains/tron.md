# Tron

Tron does NOT use the registry's generic `tron-sign-request` (5101) — the
device never answers it. Tron rides a structured envelope:
`keystone-sign-request` (6101) carrying a gzip-compressed protobuf, answered
by `keystone-sign-result` (6102). The SDK builds and parses all of it; you
supply the one thing that matters:

**`rawData` — the serialized `Transaction.raw_data` — is the signing truth.**
The device signs `sha256(rawData) = txID` and returns the transaction with
`raw_data` unmodified, so ANY contract signs: TRX transfers, TRC-20, arbitrary
dApp calldata. The display fields exist only for the device screen.

## 1. Generate the sign request

```ts
const tron = accounts.tron();       // m/44'/195'/0' — pathFor(i), deriveAddress(i), xfp
if (!tron) throw new Error('the export carries no Tron account');

const request = era.tron.generateSignRequest({
  rawData,                          // Uint8Array — Transaction.raw_data bytes
  path: tron.pathFor(0),            // "m/44'/195'/0'/0/0"
  xfp: tron.xfp,
  latestBlock: { hash, number, timestamp },   // see below
  display: {                        // optional, device screen only
    token: 'USDT',
    contractAddress: 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t',
    from, to, value: '1000000', fee: 1_000_000, decimals: 6,
  },
});
```

| Prop | Required | Notes |
|---|---|---|
| `rawData` | ✅ | From tronweb: `hexToBytes(tx.raw_data_hex)` |
| `path`, `xfp` | ✅ | From linking |
| `latestBlock` | ✅ | A LIVE now-block, with the **full 64-hex block id** — the SDK refuses a truncated hash. The device uses it to validate/rebuild the reference block and expiration |
| `display.*` | – | Safe to omit entirely for opaque dApp transactions |

```ts
import { hexToBytes } from '@hwlt/era-connect';

// tronweb
const tx = await tronWeb.transactionBuilder.sendTrx(to, amount, from);
const block = await tronWeb.trx.getCurrentBlock();
const request = era.tron.generateSignRequest({
  rawData: hexToBytes(tx.raw_data_hex),
  path, xfp,
  latestBlock: {
    hash: block.blockID,                       // full 64-hex
    number: block.block_header.raw_data.number,
    timestamp: block.block_header.raw_data.timestamp,
  },
});
```

## 2. Parse the signature

```ts
const scanner = request.scanner();   // create ONCE, feed it the camera frames
const sig = scanner.parse();
sig.txId;      // sha256(raw_data) hex — the network txID
sig.rawTx;     // hex of the COMPLETE signed transaction
sig.signedTx;  // { rawData, signatures } — split for verification
```

The reply's `signId` echo is validated for you — on Tron it is the **only**
anti-replay binding, because the device's bytes are broadcast verbatim.

## 3. Verify & broadcast

```ts
import { verifyTronSignature } from '@hwlt/era-connect/verify';

const check = verifyTronSignature({
  rawData, from: ownerAddress, latestBlock, signedTx: sig.signedTx,
});
if (!check.ok) throw new Error(check.reason);

await tronWeb.trx.sendHexTransaction(sig.rawTx);   // broadcast verbatim
```

`verifyTronSignature` recovers every signature to the owner address, then
byte-compares `raw_data` with what you sent. If a firmware rebuilt the
transaction from the display fields instead (older signing path), it falls
back to comparing the operation itself (owner/recipient/amount/calldata) and
the validity window against your reference block — an operation it cannot
compare field-by-field is refused, never waved through.
