# Cardano

Wire types: `cardano-sign-request` (2202) → `cardano-signature` (2203).

Cardano differs from the other chains in three ways the SDK absorbs:

- **You send the whole transaction, the device signs the body.** `signData` is
  the full tx CBOR array (`[body, witness_set, is_valid, aux_data]`); the
  device extracts the FIRST element and signs its BLAKE2b-256 hash.
- **The reply is a witness set, not a bare signature** —
  `{0: #6.258([[vkey, signature]…])}`, one pair per unique signing path. You
  merge it into your transaction.
- **Soft public derivation exists** (BIP32-Ed25519): from the linked account
  xpub the SDK derives payment/change/stake verification keys locally, which
  is what makes real witness binding possible in `verifyCardanoSignature`.

## 0. Linking

Cardano exports the CIP-1852 Icarus account (`m/1852'/1815'/0'`) — note its
origin keypath carries no fingerprint; the SDK resolves against the wrapper's
master fingerprint automatically.

```ts
const accounts = era.parseAccounts(scannedUr);
const ada = accounts.cardano()!;
ada.publicKey;        // 32-byte account vkey
ada.chainCode;
ada.deriveKey(0, 0);  // payment vkey #0 (role 0), change = role 1, stake = role 2
ada.pathFor(0, 0);    // "m/1852'/1815'/0'/0/0"
```

Address assembly (bech32 `addr1…`) stays with your Cardano tooling — build it
from `deriveKey(0, i)` + `deriveKey(2, 0)`.

## 1. Generate the sign request

```ts
const request = era.cardano.generateSignRequest({
  signData: txBytes,                     // FULL tx CBOR (see below)
  utxos: [{
    transactionHash,                     // 32 bytes
    index: 0,
    amount: '2000000',                   // lovelace, display
    path: ada.pathFor(0, 0),
    xfp: ada.xfp,
    address,                             // bech32, display
  }],
  certKeys: [                            // when the tx carries certificates /
    { path: ada.pathFor(2, 0), xfp: ada.xfp }, // withdrawals: the stake key
  ],
});
```

| Prop | Required | Notes |
|---|---|---|
| `signData` | ✅ | The complete serialized transaction from your tooling (`tx.to_bytes()` in CSL / `tx.toCbor()` in lucid) |
| `utxos[]` | ✅ (≥1) | One entry per input; the device signs once per UNIQUE path |
| `certKeys[]` | – | Extra witness paths (stake key for delegation/withdrawal) |
| `amount`/`address` | – | Device display — recommended |

## 2. Parse the signature

```ts
const scanner = request.scanner();   // create ONCE, feed it the camera frames
const sig = scanner.parse();
sig.witnessSet;   // CBOR bytes — merge into your tx
sig.witnesses;    // parsed [{vkey, signature}] pairs
```

## 3. Verify, assemble & broadcast

```ts
import { verifyCardanoSignature } from '@hwlt/era-connect/verify';

const check = verifyCardanoSignature({
  signData: txBytes,
  witnessSet: sig.witnessSet,
  account: {                             // binds the witnesses to YOUR wallet
    publicKey: ada.publicKey,
    chainCode: ada.chainCode,
    accountPath: ada.accountPath,
  },
  signerPaths: [ada.pathFor(0, 0)],      // the paths your request carried
});
if (!check.ok) throw new Error(check.reason);
```

With `account` + `signerPaths` the check proves the witnesses are exactly the
soft-derived children of your linked account at the requested paths — without
them it only proves the pairs are internally consistent.

Merge and submit with your tooling: set the vkey witnesses from
`sig.witnesses` into the transaction's witness set and submit the result.
