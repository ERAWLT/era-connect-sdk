# Bitcoin

Two distinct flows, honestly different on the wire:

- **Transactions** ride `crypto-psbt` (tag 310) — the raw PSBT bytes, both
  directions. No request id exists on this path, so verification of the
  returned PSBT is **mandatory**, not hygiene.
- **Messages** ride `btc-sign-request` (8101) → `btc-signature` (8102), with
  a request id like every other chain.

## 1a. Transactions — PSBT

```ts
const request = era.btc.generatePsbtSignRequest({ psbt: psbtBytes });
```

Requirements the device imposes on the PSBT:

- **PSBT v0** (BIP-174): the signer reads the global `UNSIGNED_TX`, which
  v2 (BIP-370) drops. The SDK refuses non-v0 PSBTs during verification.
- Each input carries its BIP-32 derivation plus `witnessUtxo` (segwit),
  `redeemScript` (nested segwit) or `nonWitnessUtxo` (legacy).

```ts
// bitcoinjs-lib
const psbt = new Psbt({ network });
psbt.addInput({ hash, index, witnessUtxo, bip32Derivation: [{ masterFingerprint, path, pubkey }] });
psbt.addOutput({ address, value });
const request = era.btc.generatePsbtSignRequest({ psbt: psbt.toBuffer() });
```

### Parse + verify + finalize

The reply is the **signed, NOT finalized** PSBT:

```ts
import { verifySignedPsbt } from '@era-wallet/connect/verify';

const scanner = request.scanner();   // create ONCE, feed it the camera frames
const { psbt: signed } = scanner.parse();
const check = verifySignedPsbt({ sentPsbt: psbtBytes, signedPsbt: signed });
if (!check.ok) throw new Error(check.reason);   // THE anti-replay binding — never skip

const final = Psbt.fromBuffer(Buffer.from(signed));
final.finalizeAllInputs();
await broadcast(final.extractTransaction().toHex());
```

`verifySignedPsbt` proves: same unsigned transaction byte-for-byte (inputs,
outputs, amounts, txid), no finalized script fields the device did not receive,
every input signed (pass `requireEveryInputSigned: false` for dApp `signPsbt`
hand-backs where some inputs are not yours).

## 1b. Messages

**The device signs messages for legacy P2PKH (`1…`) addresses only** — use
the purpose-44 account, not the default segwit one:

```ts
const legacy = accounts.btc({ purpose: 44 });   // the BIP-44 legacy account
if (!legacy) throw new Error('the export carries no legacy account');

const request = era.btc.generateMessageSignRequest({
  message: utf8Bytes,
  path: legacy.receivePath(0),                  // m/44'/0'/0'/0/0
  xfp: legacy.xfp,
  address: legacy.deriveAddress(0),             // '1…'
});
```

A segwit address produces an empty reply, which `parse()` surfaces as
`EraSdkError('empty-signature')` with that explanation — show it to the user
instead of a generic failure.

```ts
const scanner = request.scanner();   // create ONCE, feed it the camera frames
const sig = scanner.parse();
sig.signature;        // raw 65-byte BIP-137 (the wire carries base64-as-ASCII;
sig.signatureBase64;  //   the SDK undoes that quirk for you)
```

`verifyBtcMessageHeader({ address, signature })` checks the BIP-137 recovery
header names the right address kind — a wrong header LOOKS like a success on
your side and fails in every downstream verifier.
