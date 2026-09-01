# Bitcoin Cash

Bitcoin Cash does NOT ride the PSBT path the rest of the Bitcoin family uses:
BCH consensus requires the BIP-143 sighash with `SIGHASH_FORKID` (0x41), which
the device's PSBT signer cannot apply. Instead the device runs a dedicated
FORKID signer behind the same structured envelope Tron uses —
`keystone-sign-request` (6101) carrying a gzip-compressed protobuf, answered
by `keystone-sign-result` (6102).

That makes BCH the one chain where this SDK is more than a transport: you
hand it structured UTXOs and outputs, and it builds the transaction container
the device signs. The device derives each input's key from its `path`, signs
every input with `SIGHASH_ALL | SIGHASH_FORKID`, and returns the **complete
broadcastable transaction**.

Fixed signer parameters (not configurable): version 1, locktime 0, input
sequence `0xfffffffd`, P2PKH inputs only. Outputs may pay P2PKH or P2SH
CashAddr addresses.

## 1. Generate the sign request

```ts
const bch = accounts.bch()!;                    // m/44'/145'/0' from linking

const request = era.bch.generateSignRequest({
  inputs: [{
    txid: '142f…144a',                          // display-order txid, 64 hex
    index: 0,
    value: 250000,                              // satoshis — MUST be exact
    publicKey: bch.derivePublicKey(0),          // the UTXO owner's key
    path: bch.receivePath(0),                   // m/44'/145'/0'/0/0
  }],
  outputs: [
    { address: 'qpm2…dx6a', value: 80000 },     // CashAddr, prefixed or bare
    {
      address: bch.deriveAddress(0, { change: true }),
      value: 169000,
      isChange: true,                           // display only
      changeAddressPath: bch.changePath(0),
    },
  ],
  fee: 1000,                                    // MUST equal inputs − outputs
  xfp: bch.xfp,
});
```

| Prop | Required | Notes |
|---|---|---|
| `inputs[].txid` | ✅ | Display-order (big-endian), exactly as explorers and UTXO APIs show it |
| `inputs[].value` | ✅ | Part of the BIP-143 sighash — a wrong value produces a signature the network rejects |
| `inputs[].publicKey` | ✅ | 33-byte compressed key; get it from `accounts.bch().derivePublicKey(i)` |
| `inputs[].path` | ✅ | The device derives the signing key from THIS, per input |
| `outputs[].address` | ✅ | CashAddr only (P2PKH `q…` / P2SH `p…`), with or without `bitcoincash:`; legacy base58 is refused. Any spec-legal spelling is accepted — including the all-uppercase QR form — and the SDK rewrites it to the canonical lowercase form on the wire (the device parses only that) |
| `fee` | ✅ | Shown on the device screen; the SDK refuses a fee that does not equal `sum(inputs) − sum(outputs)` |
| `dustThreshold` | – | Defaults to 546 |
| `memo`, `timestamp` | – | Display/log only |

Every output — change included — carries a real address: the device builds
the output script from it. `isChange`/`changeAddressPath` only label it on
the review screen.

## 2. Parse the signature

```ts
const scanner = request.scanner();   // create ONCE, feed it the camera frames
const sig = scanner.parse();
sig.txId;      // display-order txid, as computed by the device
sig.rawTx;     // hex of the COMPLETE signed transaction
```

The reply's `signId` echo is validated for you. As on Tron it is the only
anti-replay binding in the envelope — which is why the next step is not
optional.

## 3. Verify & broadcast

```ts
import { verifyBchSignedTx } from '@hwlt/era-connect/verify';

const check = verifyBchSignedTx({
  rawTx: sig.rawTx,
  inputs,        // the same txid/index/value/publicKey you sent
  outputs,       // the same address/value you sent
  txId: sig.txId,
});
if (!check.ok) throw new Error(check.reason);

// Broadcast the raw hex with any BCH API, e.g. a Fulcrum/Electrum server or
// a REST endpoint that accepts `sendrawtransaction`.
```

`verifyBchSignedTx` rebuilds the whole binding from the returned bytes:
every outpoint and output must match the request, each input's scriptSig must
carry the requested public key and sighash type 0x41, and each signature is
re-verified against a locally recomputed BIP-143 FORKID sighash. A
substituted destination, a tampered value, or a signature by a different key
all fail closed.

## Address utilities

The subpath also exports the CashAddr codec — no extra dependency needed:

```ts
import { decodeCashAddr, encodeCashAddr } from '@hwlt/era-connect/bch';

decodeCashAddr('bitcoincash:qphc…qkva');  // { type: 'p2pkh', hash, prefix }
encodeCashAddr('p2pkh', hash160, { withPrefix: true });
```

`accounts.bch()` derives receive/change addresses locally
(`deriveAddress(i)`, bare CashAddr by default, `{ withPrefix: true }` for the
`bitcoincash:` form).
