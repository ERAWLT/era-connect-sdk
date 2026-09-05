# XRP

XRP rides the **XRP Toolkit convention**: an untyped `ur:bytes` both ways —
the request wraps the transaction JSON, the reply wraps the canonical signed
XRPL binary. Two consequences the SDK makes explicit:

- **There is no request id on this wire.** Like Bitcoin PSBTs, the binding is
  the content — which is why `verifyXrpSignature` is not optional here.
- **The device signs with `m/44'/144'/0'/0/0`, always.** Your transaction
  JSON must already carry that key's hex in `SigningPubKey`.

## 0. Accounts

`accounts.xrp()` is the linked `m/44'/144'/0'` account, and it produces the one
key this chain uses:

```ts
import { bytesToHex } from '@hwlt/era-connect';

const xrp = accounts.xrp();
// Two conditions, not one: a view can also come back for an entry at the
// LEAF path — see the section below for why, and what to do then.
if (!xrp || xrp.accountPath !== "m/44'/144'/0'") {
  throw new Error('the export carries no XRP account');
}

xrp.signingPath;                            // "m/44'/144'/0'/0/0" — the only path signed
const SigningPubKey = bytesToHex(xrp.derivePublicKey(0)).toUpperCase();
xrp.deriveAddress(0);                       // the classic 'r…' Account
xrp.pathFor(3);                             // further addresses of the same account
```

`SigningPubKey` is not decoration a library can default: on XRPL the signing
key is part of the signed payload, so a transaction naming any other key is
invalid before it ever reaches the device. Derive it once at link time and keep
it — it is also what you hand the verifier below.

### When the export carries the leaf, not the account

"The device signs with `m/44'/144'/0'/0/0`" makes that the obvious path to ask
a `generateKeyDerivationCall` for — and the device answers with an entry AT
that path: the signing key itself, with nothing left to derive.

An entry is classified by its first TWO path levels only, so the leaf is an
`'xrp'` entry exactly like the account is, and `accounts.xrp()` wraps it too —
as an "account" one level too deep:

| | account entry `m/44'/144'/0'` | leaf entry `m/44'/144'/0'/0/0` |
|---|---|---|
| `accountPath` | `m/44'/144'/0'` | `m/44'/144'/0'/0/0` |
| `signingPath` | `m/44'/144'/0'/0/0` — the signing key | `m/44'/144'/0'/0/0/0/0` — nothing signs there |
| `derivePublicKey(0)` | the signing key | a grandchild of it |

Nothing throws and `if (!xrp)` does not fire: a view comes back, its
`deriveAddress(0)` is a well-formed `r…` address, and it belongs to a key the
device will never sign with — a transaction built on it is rejected by the
ledger, not by the SDK. So branch on the PATH you asked for rather than on
whether a view exists: take the leaf's key straight off the entry, and use the
view only when it really wraps the account.

```ts
import type { EraAccounts } from '@hwlt/era-connect';

const ACCOUNT = "m/44'/144'/0'";
const LEAF = `${ACCOUNT}/0/0`;

function signingPublicKey(accounts: EraAccounts): Uint8Array {
  // Pulled leaf: the entry IS the key — read it, do not derive from it.
  const leaf = accounts.keys.find((k) => k.path === LEAF);
  if (leaf?.publicKey) return leaf.publicKey;
  // Volunteered account: `signingPath` names 0/0 and `derivePublicKey(0)` is it.
  const view = accounts.xrp();
  if (view?.accountPath === ACCOUNT) return view.derivePublicKey(0);
  throw new Error('the export carries no XRP key');
}

const SigningPubKey = bytesToHex(signingPublicKey(accounts)).toUpperCase();
```

The request itself carries no path and no fingerprint on this chain — it is a
bare `ur:bytes` holding the transaction JSON — so which of the two shapes your
export has changes only where the key comes from, never what you send.

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
