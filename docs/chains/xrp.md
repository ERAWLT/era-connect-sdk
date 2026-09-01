# XRP

XRP rides the **XRP Toolkit convention**: an untyped `ur:bytes` both ways —
the request wraps the transaction JSON, the reply wraps the canonical signed
XRPL binary. Two consequences the SDK makes explicit:

- **There is no request id on this wire.** Like Bitcoin PSBTs, the binding is
  the content — which is why `verifyXrpSignature` is not optional here.
- **The device signs with `m/44'/144'/0'/0/0`, always.** Your transaction
  JSON must already carry that key's hex in `SigningPubKey` (get it from the
  linked wallet's XRP entry).

```ts
// 1 · request — a ready unsigned tx JSON (TransactionType, r…-Account,
//     Fee, Sequence and SigningPubKey are validated before anything is shown)
const request = era.xrp.generateSignRequest({
  transaction: {
    TransactionType: 'Payment',
    Account: 'r…', Destination: 'r…', Amount: '1000000',
    Fee: '12', Sequence, SigningPubKey,
  },
});

// 2 · reply
const scanner = request.scanner();
const { signedTx } = scanner.parse();   // canonical signed binary

// 3 · verify (MANDATORY — this IS the binding) + submit
import { verifyXrpSignature } from '@hwlt/era-connect/verify';
const check = verifyXrpSignature({ signedTx, expectedSigningPubKey: SigningPubKey });
if (!check.ok) throw new Error(check.reason);
await client.submit(bytesToHex(signedTx));   // rippled submit (tx_blob)
```

The verifier splits the canonical binary, recomputes the XRPL signing hash
(`STX\0` prefix, SHA-512-half) without `TxnSignature`, and checks the DER
signature against `SigningPubKey` — which must equal the key your request
carried. A transaction using exotic field types comes back `checked: false`
rather than a false verdict.
