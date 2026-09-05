# 2. Link the device

The user opens **Connect / sync** on their ERA device; it displays an animated
QR of type `crypto-multi-accounts` — the extended public keys for every chain.
You scan it once, then derive addresses locally forever. The device is not
needed again until something must be signed.

## Scan the export

```ts
import { WALLET_UR_TYPES } from '@hwlt/era-connect';

const scanner = era.scanner({ expectedTypes: WALLET_UR_TYPES });

function onCameraFrame(text: string) {
  const result = scanner.receivePart(text);
  switch (result.kind) {
    case 'progress':   // update your progress bar: result.progress ∈ [0, 1]
      break;
    case 'complete': {
      const accounts = era.parseAccounts(result.ur);
      // done — see below
      break;
    }
    case 'rejected':   // a frame that is not part of this export
      // result.rejection = { code, message, repeated } — repeated counts
      // consecutive identical rejections, so log/toast ONCE, not per frame
      break;
    case 'duplicate':  // the camera saw the same frame again; ignore
      break;
  }
}
```

`expectedTypes` is not cosmetic: frames of any other UR type are refused
*before* the decoder can commit to them, which is what keeps a hostile QR in
the camera frame (a sticker, a poster) from hijacking the scan.

Pin it to `WALLET_UR_TYPES` rather than to a literal. A device links with one
of three UR types, and the multichain export is only the common one — TON, for
example, is exported as a standalone `crypto-hdkey`. A hand-written
`['crypto-multi-accounts']` refuses every frame of such a link, which looks
like a camera problem and is not.

`WALLET_UR_TYPES` is a frozen `readonly string[]`, so hand it to
`expectedTypes` as it is — no copy, and nothing a caller can widen.

## What you get

```ts
const accounts = era.parseAccounts(result.ur);

accounts.masterFingerprint;      // 'deadbeef' — 8-hex master fingerprint
accounts.device;                 // { name, id, firmwareVersion }
accounts.keys;                   // every exported account, chain-classified

const evm = accounts.evm()!;     // undefined if the export carries no EVM account
evm.xfp;                         // ← goes into every sign request
evm.pathFor(0);                  // "m/44'/60'/0'/0/0"
evm.deriveAddress(0);            // '0x…' (EIP-55), derived locally
evm.xpub();                      // extended public key, if you prefer your own tooling

const btc = accounts.btc()!;     // the BIP-84 native-segwit MAINNET account
btc.deriveAddress(0);                    // 'bc1q…' receive
btc.deriveAddress(0, { change: true });  // change branch
btc.zpub();                              // SLIP-132 form for wallet tooling

accounts.btc({ testnet: true });         // a DIFFERENT account — m/84'/1'/0'

const sol = accounts.solana();   // Ed25519 has no public derivation — the
sol[0].address;                  // device pre-derives m/44'/501'/0'..9';
sol[0].path;                     // each entry IS a signer

const tron = accounts.tron()!;
tron.deriveAddress(0);           // 'T…'

const bch = accounts.bch()!;     // m/44'/145'/0'
bch.deriveAddress(0);            // bare CashAddr ('q…')
```

**Persist `accounts.sourceUr`** (the raw UR string) — re-parse it any time you
need more addresses. Do not persist derived state you can re-derive.

Three rules that save debugging later:

- **Identify chains by derivation path, never by the `note` label.** The note
  is a display string (`account.standard`, …), not chain metadata.
- **The xfp you put in sign requests is per-account** (`view.xfp` /
  `accounts.xfpFor(path)`), NOT the master fingerprint. They often coincide —
  until they don't.
- **`btc({ testnet: true })` SELECTS an account, it does not re-render one.**
  It matches the export's entry at `m/<purpose>'/1'/…` and returns `undefined`
  when there is none — never the mainnet account under a testnet address.
  ERA firmware exports Bitcoin accounts at coin type `0'` only, so for a wallet
  linked from an ERA device the answer is `undefined`; the option is there
  because the export format carries coin-type-`1'` accounts and other wallet
  profiles populate them. Details in [Bitcoin](../chains/bitcoin.md).

Next: [Display a sign request →](03-display-request.md)
