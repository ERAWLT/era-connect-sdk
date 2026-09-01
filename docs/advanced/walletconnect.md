# Backing a WalletConnect wallet

If your wallet speaks WalletConnect, the device backs it directly: take the
dApp's payload, wrap the raw bytes VERBATIM in the matching sign request, and
forward the device's signature. Do not pre-parse, do not reject what your app
does not understand — the device parses the payload and decides what it can
sign; its screen is the review surface.

## Method → request mapping

| WC method | Build with | dataType / notes |
|---|---|---|
| `eth_sendTransaction` / `eth_signTransaction` | `era.evm.generateSignRequest` | `transaction`; signData = the tx RLP-encoded for signing |
| `personal_sign` / `eth_sign` | `era.evm.generateSignRequest` | `personalMessage`; the RAW message bytes (no prefix) |
| `eth_signTypedData*` | `era.evm.generateSignRequest` | `typedData`; the JSON as UTF-8 bytes |
| `solana_signTransaction` / `signAndSendTransaction` | `era.solana.generateSignRequest` | the message bytes from the dApp tx |
| `solana_signMessage` | `era.solana.generateSignRequest` | `signType: message` |
| bip122 `signPsbt` | `era.btc.generatePsbtSignRequest` | verify with `requireEveryInputSigned: false` (a dApp PSBT may carry inputs that are not yours), then hand the signed PSBT back — do not finalize |
| bip122 `signMessage` | `era.btc.generateMessageSignRequest` | legacy P2PKH only — see the Bitcoin guide |
| `tron_signTransaction` / `tron_sendTransaction` | `era.tron.generateSignRequest` | `rawData` = bytes of the dApp's `raw_data_hex`, display fields left empty (the tx is opaque to you — the device decodes it) |
| `tron_signMessage` | `era.tron.generateSignRequest` | the UTF-8 message bytes travel in `rawData` — Tron has no separate message type. `latestBlock` is still REQUIRED (the envelope demands a live now-block with the full 64-hex id, even for a message) |

## Result shapes dApps expect

| Method | JSON-RPC result |
|---|---|
| `eth_*` transaction | bare hex of the signed raw tx |
| `personal_sign` / `eth_sign` / `eth_signTypedData*` | bare hex `0x{r‖s‖v}` (map parity → 27/28) |
| `solana_signTransaction` | `{ signature: base58 }` |
| `solana_signMessage` | `{ signature: base58 }` |
| bip122 `signPsbt` | `{ psbt: base64 }` — the signed, NOT finalized PSBT |
| bip122 `signMessage` | `{ address, signature: base64 }` (BIP-137) |
| `tron_signTransaction` | the dApp's tx object echoed with `signature: [hex]` (from `sig.signedTx.signatures`) |
| `tron_signMessage` | `{ signature: '0x…' }` |

Always show the recipient/calldata in your own UI before displaying the QR —
what the user sees in your app should match what the device will show. The
verification helpers run the same as in first-party flows (with the PSBT and
EIP-712 caveats above).
