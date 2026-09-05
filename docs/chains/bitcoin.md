# Bitcoin

Two distinct flows, honestly different on the wire:

- **Transactions** ride `crypto-psbt` (tag 310) — the raw PSBT bytes, both
  directions. No request id exists on this path, so verification of the
  returned PSBT is **mandatory**, not hygiene.
- **Messages** ride `btc-sign-request` (8101) → `btc-signature` (8102), with
  a request id like every other chain.

## 0. Accounts: purpose and network

`accounts.btc()` returns the linked BIP-84 (native segwit) **mainnet**
account. `purpose` picks another script type, `testnet` picks another network:

```ts
accounts.btc();                               // m/84'/0'/0' — bc1q…, xpub/zpub
accounts.btc({ purpose: 44 });                // m/44'/0'/0' — 1…
accounts.btc({ purpose: 49 });                // m/49'/0'/0' — 3…
accounts.btc({ testnet: true });              // m/84'/1'/0' — tb1q…, tpub/vpub
accounts.btc({ testnet: true, purpose: 49 }); // m/49'/1'/0' — 2…
```

`purpose` is bounded to **44, 49, 84 and 86**, at runtime and not only by its
type. Any other number returns `undefined` rather than a view: an arbitrary
purpose has no script type and no address encoding, so a view over it could
serve a plausible-looking `xpub()` and refuse only later, at the first
address.

**`testnet` selects an account; it does not re-render one.** The match is the
export's own entry at `m/<purpose>'/1'/…`, and the answer is `undefined` when
the export carries no such entry. There is deliberately no fallback to the
mainnet account: a mainnet key printed under a testnet HRP is a wrong answer
that looks right — same path, same fingerprint, same key, a different address.

Only those first two levels are examined, on either network, and the FIRST
matching entry wins — an export whose only BIP-84 testnet entry is
`m/84'/1'/2'` answers with that one, so read `accountPath` rather than
assuming a `0'` account index. Both levels must be **hardened**: a
`crypto-keypath` can spell a soft level, and `m/84'/1/0'` is a different key,
not a testnet account.

Everything on the returned view follows the account it was selected for: the
addresses, `accountPath` / `receivePath()` / `changePath()`, the `xfp` your
sign requests carry, and the extended keys — `xpub()` returns the `tpub…` form
and `zpub()` the `vpub…` form (the SLIP-132 BIP-84 testnet key; the method
keeps its name and still refuses any purpose other than 84).

**ERA firmware exports Bitcoin accounts at coin type `0'` only.** For a wallet
linked from an ERA device, `accounts.btc({ testnet: true })` is therefore
`undefined` for every purpose — that is the truthful answer, not a gap. The
option stays because the export format carries coin-type-`1'` accounts and
other wallet profiles populate them.

One consequence worth knowing before you go looking for it: `accounts.keys`
reports a coin-type-`1'` entry as `chain: 'unknown'`, and that is deliberate.
SLIP-44 assigns coin type 1 to "Testnet (all coins)", so `m/84'/1'/0'` is as
much a Litecoin testnet account as a Bitcoin one. With no caller intent to
lean on, the classifier says nothing rather than guessing; `btc({ testnet:
true })` resolves that same path only because you named the chain.

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
(`accounts.keys` carries them with `chain: 'unknown'` — the classifier maps
only coin-type 0' to `btc`; find these entries by their derivation path).
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
