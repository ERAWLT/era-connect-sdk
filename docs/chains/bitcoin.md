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
import { verifySignedPsbt } from '@hwlt/era-connect/verify';

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

## 1a-bis. Litecoin, Dogecoin, Dash — same PSBT flow

The Bitcoin-family coins ride the SAME code path via `crypto-psbt-extend`
(the PSBT plus a coin id, answered in kind). Build the PSBT with the coin's
own derivation paths and pass `coin`:

```ts
const request = era.btc.generatePsbtSignRequest({ psbt, coin: 'ltc' }); // 'doge' | 'dash'
```

Everything else — the signed-not-finalized reply, `verifySignedPsbt` as the
mandatory binding, finalize + broadcast with your own stack — is identical.
Linked account paths: LTC `m/84'/2'/0'`, DOGE `m/44'/3'/0'`, DASH `m/44'/5'/0'`
(`accounts.keys` carries them; they classify as `btc`-family by path).
Bitcoin Cash is NOT offered on this path — its FORKID sighash needs the
device's structured envelope. It has its own module: see
[Bitcoin Cash](bch.md) (`@hwlt/era-connect/bch`).

## 1b. Messages

**Which addresses are message-signable depends on the firmware.** Firmware
2.1.0 and newer signs for BIP-44 legacy, BIP-49 nested-segwit and BIP-84
native-segwit addresses, each with its proper BIP-137 header range (Taproot
is refused — BIP-137 has no header for it, BIP-322 is a different scheme).
Older firmware signs legacy P2PKH (`1…`) only. The legacy account is the
safe choice across every firmware:

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

On firmware 2.1.0+ the `xfp` is mandatory — the device refuses a message
request without a source fingerprint (a message carries no other proof of
ownership), and the path must be a full 5-level BIP-44 path. An address kind
the firmware cannot sign for produces an empty reply, which `parse()`
surfaces as `EraSdkError('empty-signature')` with that explanation — show it
to the user instead of a generic failure.

```ts
const scanner = request.scanner();   // create ONCE, feed it the camera frames
const sig = scanner.parse();
sig.signature;        // raw 65-byte BIP-137. Firmware 2.1.0+ sends the raw
sig.signatureBase64;  //   bytes; older firmware sends base64-as-ASCII — the
                      //   SDK accepts both and hands you both forms
```

`verifyBtcMessageHeader({ address, signature })` checks the BIP-137 recovery
header names the right address kind — a wrong header LOOKS like a success on
your side and fails in every downstream verifier.
