# Device specifics vs the Keystone registry

The ERA device implements the Keystone-compatible UR registry with a short
list of exact behaviors. **The SDK already encodes every one of them** — this
page exists so none of them ever surprises you, and as the checklist for
anyone implementing the wire format without the SDK.

| Area | Device behavior | Where the SDK handles it |
|---|---|---|
| Request id echo | Replies ALWAYS wrap the echoed id in CBOR tag 37, even when the request sent it untagged (EVM/Solana requests do). Compare BYTES, tag-agnostically | `parse()` on every chain |
| EVM `dataType` | `1` and `4` are equivalent; the tx kind (EIP-1559 / 2930 / legacy) is sniffed from the leading RLP byte | docs only — send `transaction` |
| EVM legacy `v` | Returned ALREADY EIP-155-encoded (`parity + chainId·2 + 35`), minimal-width big-endian — more than one byte past chain id 110 | `EvmSignatureResult.v` is as-sent; `recoveryId` folds it |
| EVM `chainId` | Parsed as an unsigned 32-bit value; larger ids would truncate silently and sign for a different chain | `generateSignRequest` refuses `chainId > 0xFFFFFFFF` |
| EVM large payloads | `signData` > 32 KiB falls back to blind signing (no decoded display) | `warnings: ['blind-sign-threshold']` |
| `eth-signature` vs `evm-signature` | The device answers with `eth-signature` (402); `evm-signature` (4102) belongs to the Cosmos/Ethermint family. Both are accepted on parse | `replyTypes` |
| Bitcoin PSBT | Bare CBOR byte string both directions, **no request id** — the returned PSBT's unsigned-tx comparison IS the anti-replay binding. PSBT v0 required (the signer reads the global `UNSIGNED_TX`) | `verifySignedPsbt` (mandatory) |
| Bitcoin messages | Firmware-dependent. 2.1.0+: BIP-44/49/84 signable with proper BIP-137 headers, Taproot refused, `xfp` mandatory, reply is the RAW 65-byte signature. Older: legacy P2PKH only, segwit returns an EMPTY signature, reply bytes are the **ASCII of a base64 string** | typed `empty-signature`; `parse()` accepts both reply forms |
| Solana signing | Bytes signed VERBATIM (versioned txs fine). The signer key is the **leading hardened run** of the request path — a 5-level path signs with its 3-level hardened prefix | 3-level path enforced at build |
| Solana legacy replies | Older firmware sent the signature as a hex TEXT string instead of bytes | both accepted |
| Tron envelope | `keystone-sign-request` (6101) gzip-protobuf; the generic `tron-sign-request` (5101) is not wired and gets NO response | the SDK only emits 6101 |
| Tron xfp | Inside the protobuf the fingerprint is a lowercase hex STRING **zero-padded to 8 chars** — unpadded, one wallet in 256 (leading zero byte) cannot sign at all | padded at build |
| Tron reply caps | gzip reply: ≤ 8 KiB compressed, ≤ 64 KiB inflated, streamed with the ISIZE truncation check | `limit-exceeded` / `gzip-error` |
| Tron anti-replay | The protobuf `signId` echo (case-insensitive UUID) is the only binding — device bytes are broadcast verbatim | checked in `parse()` |
| TON request id | ASCII bytes of the UUID STRING (tag 37) — not the 16-byte binary form other chains use; the echo is those bytes verbatim | emitted/normalized by the TON module |
| TON digests | transaction = BoC ROOT CELL representation hash; TON Connect proof = `sha256(0xFFFF‖"ton-connect"‖sha256(payload))` | recomputed by `verifyTonSignature` |
| TON linking | standalone minimal `crypto-hdkey` (`{key, keypath, name}`), not the multichain export; V4R2/V5R1 share the key — the contract version only changes the address | `parseAccounts` + `accounts.ton()` |
| Cardano signData | The FULL tx CBOR array; the device signs BLAKE2b-256 of the ENCODED FIRST ELEMENT (the body) | digest recomputed by `verifyCardanoSignature` |
| Cardano reply | A witness set `{0: #6.258([[vkey, sig]…])}` — one pair per unique signing path across utxos + certKeys | parsed into `witnesses`; set tag optional on parse |
| Cardano linking | The account entry's origin keypath carries NO fingerprint (path-only) — resolve against the wrapper's master fingerprint | automatic in `parseAccounts` |
| Sui hash requests | `sui-sign-hash-request` carries the 32-byte digest as a HEX STRING, not bytes | handled by `generateSignHashRequest` |
| Cosmos vs Ethermint | Same CBOR tag (4101), different UR type strings; Ethermint signs keccak-256 over `m/44'/60'` keys and its address field is the ASCII bytes of the `0x` string | two builders on `era.cosmos` |
| XRP wire | Untyped `ur:bytes` both ways (JSON in, signed binary out); NO request id — content verification is the only binding; the device always signs with `m/44'/144'/0'/0/0` | `verifyXrpSignature` mandatory |
| Bitcoin family | LTC/DOGE/DASH ride `crypto-psbt-extend` = `{1: PSBT, 2: coin id}` (2/3/5), answered in kind; BCH is refused on the PSBT path (no FORKID there) | `coin` option on `generatePsbtSignRequest` |
| Bitcoin Cash | rides the Tron-style `keystone-sign-request` envelope: gzip protobuf, `BchTx` with FLAT inputs, per-input `ownerKeyPath`, CashAddr outputs; reply is the COMPLETE signed transaction (version 1, locktime 0, sequence `0xfffffffd`, sighash 0x41) | the whole `bch` module + `verifyBchSignedTx` |
| UR on the wire | Frames render UPPERCASE (QR alphanumeric mode); parsing is case-insensitive | `nextFrame()` / scanner |
| QR asymmetry | Phone→device ~200 B frames at 8 fps; device→phone 150 B at 2.5 fps | `DeviceProfile` |
| `origin` | Free-form label shown on the device for context; not security-relevant | config / per-request |

The device's chain list keeps growing. For a chain this SDK has no module for
yet, `era.raw` + `era.scanner({expectedTypes})` speak any UR type; the
[protocol spec](../protocol/era-hardware-wallet-integration.md) has the
byte-level layouts.
