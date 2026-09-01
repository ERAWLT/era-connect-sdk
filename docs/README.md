# ERA Connect SDK — Documentation

Integrate the **ERA hardware wallet** into your software wallet over
air-gapped animated QR codes. Five steps, ten chain families, one SDK.

## Getting started (read in order — ~15 minutes to a working signature)

1. [Install & set up](getting-started/01-install.md)
2. [Link the device](getting-started/02-link-device.md) — scan `crypto-multi-accounts`, derive addresses locally
3. [Display a sign request](getting-started/03-display-request.md) — animated QR out
4. [Scan the signature](getting-started/04-scan-signature.md) — animated QR in
5. [Verify & broadcast](getting-started/05-broadcast.md) — prove it, then send it with your stack

## Per-chain guides

- [EVM](chains/evm.md) — transactions, personal_sign, EIP-712
- [Bitcoin](chains/bitcoin.md) — PSBT v0, message signing
- [Solana](chains/solana.md) — transactions (incl. versioned), off-chain messages
- [Tron](chains/tron.md) — any contract via `rawData`
- [TON](chains/ton.md) — BoC root-hash signing, TON Connect proofs
- [Cardano](chains/cardano.md) — witness sets, soft-derived vkey binding
- [Sui](chains/sui.md) — intent-message signing, local address derivation
- [Cosmos](chains/cosmos.md) — ~35 zones incl. Ethermint in one module
- [XRP](chains/xrp.md) — the XRP Toolkit `ur:bytes` convention
- Litecoin / Dogecoin / Dash — see [Bitcoin](chains/bitcoin.md) (`crypto-psbt-extend`)
- [Bitcoin Cash](chains/bch.md) — the FORKID envelope, CashAddr, full-tx verification

Anything newer the device learns speaks standard UR types through `era.raw`
and the scanner — see the
[chain-support table](../packages/connect/README.md#chain-support).

## Advanced

- [Device specifics](advanced/device-specifics.md) — exact deviations from the Keystone registry, and why
- [Verification](advanced/verification.md) — "did the device sign exactly what I sent?"
- [QR tuning](advanced/qr-tuning.md) — fragment sizes, frame rates, progress and timeouts
- [Key derivation calls](advanced/key-derivation-call.md) — the wallet asks the device for specific paths
- [WalletConnect](advanced/walletconnect.md) — backing a WC wallet with the device (forwarding model + result shapes)
- [Migrating from @keystonehq/keystone-sdk](advanced/migrating-from-keystone-sdk.md)

## Protocol

[`protocol/era-hardware-wallet-integration.md`](protocol/era-hardware-wallet-integration.md)
is the normative wire specification (UR/CBOR layouts, per-chain byte formats).
The SDK encodes it; the spec is what you implement if you cannot use the SDK.
