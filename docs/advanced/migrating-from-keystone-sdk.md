# Migrating from @keystonehq/keystone-sdk

The wire protocol is Keystone-compatible, so a migration is mechanical — the
concepts map one-to-one and most prop names are identical.

| Keystone | ERA Connect |
|---|---|
| `new KeystoneSDK({ origin })` | `new EraConnect({ origin })` |
| `sdk.parseMultiAccounts(ur)` | `era.parseAccounts(ur)` → richer `EraAccounts` (chain views, local address derivation, xpub/zpub) |
| `sdk.eth.generateSignRequest({...})` | `era.evm.generateSignRequest({...})` — same flat props (`requestId`, `signData`, `dataType`, `path`, `xfp`, `chainId`, `address`, `origin`); `signData` is `Uint8Array`, not hex |
| `sdk.eth.parseSignature(ur)` | `era.evm.parseSignature(ur, { requestId })` — **and `request.scanner().parse()` validates the echo for you, which Keystone never does** |
| `sdk.btc.generatePSBT(buffer)` | `era.btc.generatePsbtSignRequest({ psbt })` |
| `sdk.sol.generateSignRequest({...})` | `era.solana.generateSignRequest({...})` — the `dataType`/`signType` naming drift is gone (it is `signType`, as on the wire) |
| `sdk.tron.generateSignRequest({...})` | `era.tron.generateSignRequest({...})` — `signData` hex → `rawData` bytes + explicit `latestBlock` |
| `@keystonehq/animated-qr` | none needed: `request.toAnimated()` + your QR component (~10 lines, works in React Native — see [getting started](../getting-started/03-display-request.md)) |
| `URDecoder` from `@ngraveio/bc-ur` | `era.scanner()` / `request.scanner()` — same fountain decoding plus type pinning, hostile-frame binding rules and typed, repeat-deduplicated rejections |

What you gain that has no Keystone equivalent:

- **Request-id echo enforcement** in `parse()` (stale-reply replay refused).
- **`@hwlt/era-connect/verify`** — cryptographic proof the device signed
  your exact bytes, including the mandatory PSBT binding.
- **Typed errors** (`EraSdkError.code`) instead of `Error('type not match')`.
- **One package, subpath exports** — no 18-package constellation; unused
  chains stay out of your bundle.
- **No network calls** — Keystone's `KeystoneSDK.create()` fetches a remote
  config at init; nothing here ever touches the network.

Differences to check during the port:

- Byte inputs are `Uint8Array` everywhere (no implicit hex strings, no Buffer).
- Tron uses the structured envelope with an explicit `latestBlock` — the
  registry's `tron-sign-request` type is NOT accepted by the device.
- Bitcoin message signing is firmware-dependent: 2.1.0+ signs BIP-44/49/84
  (Taproot refused, `xfp` required); older firmware is legacy-P2PKH-only.
