# Key derivation calls (pull-model linking)

Normal linking is push: the device shows what its sync profile exports. A
**`qr-hardware-call`** (1201) inverts it — your wallet displays a QR asking
the device for SPECIFIC derivation paths, curves and algorithms, and the
device answers with a `crypto-multi-accounts` export of exactly that.

Use it when you need an account the default export does not carry (a
different BIP-44 account index, an extra chain the device supports but does
not volunteer, a non-default scheme).

```ts
const call = era.generateKeyDerivationCall({
  schemas: [
    { path: "m/44'/60'/1'" },                        // second EVM account
    { path: "m/44'/501'/3'", curve: 'ed25519' },     // 4th Solana signer
  ],
});

// Same display/scan cycle as a sign request:
const animated = call.toAnimated();          // render at ~8 fps
const scanner = call.scanner();              // pre-pinned to wallet-export types
// ... feed camera frames ...
const accounts = scanner.parse();            // EraAccounts, same as normal linking
```

| Schema field | Default | Values |
|---|---|---|
| `path` | — | The account-level derivation path to request |
| `curve` | `secp256k1` | `secp256k1` \| `ed25519` |
| `algo` | `slip10` | `slip10` \| `bip32ed25519` |
| `chainType` | – | Optional display hint |

Compatibility note: the call is part of the shared registry and reserved by
the device's UR table, but not every firmware answers it. A device that does
not handle it stays silent — nothing on its screen changes — so treat a
no-response within your scan timeout as "fall back to normal sync linking"
rather than as an error, and keep that fallback in the flow you ship.
