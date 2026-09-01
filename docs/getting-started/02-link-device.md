# 2. Link the device

The user opens **Connect / sync** on their ERA device; it displays an animated
QR of type `crypto-multi-accounts` — the extended public keys for every chain.
You scan it once, then derive addresses locally forever. The device is not
needed again until something must be signed.

## Scan the export

```ts
const scanner = era.scanner({ expectedTypes: ['crypto-multi-accounts'] });

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

const btc = accounts.btc()!;     // the BIP-84 native-segwit account
btc.deriveAddress(0);                    // 'bc1q…' receive
btc.deriveAddress(0, { change: true });  // change branch
btc.zpub();                              // SLIP-132 form for wallet tooling

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

Two rules that save debugging later:

- **Identify chains by derivation path, never by the `note` label.** The note
  is a display string (`account.standard`, …), not chain metadata.
- **The xfp you put in sign requests is per-account** (`view.xfp` /
  `accounts.xfpFor(path)`), NOT the master fingerprint. They often coincide —
  until they don't.

Next: [Display a sign request →](03-display-request.md)
