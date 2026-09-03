# ERA Hardware Wallet — Third-Party Integration Guide

> Integrate any software wallet with the **ERA hardware wallet** over **air‑gapped
> animated QR codes**. This document is a self-contained protocol specification: it
> describes the wire formats (UR / CBOR), key derivation and the per-chain signing
> flows you need, with runnable examples in **Dart, Kotlin, Swift and TypeScript**.

The ERA hardware wallet is an **air-gapped** signer. It never exposes private keys; it
shares **public keys** for watch-only address derivation and **signs transactions
offline**. All communication happens through **animated QR codes** encoded with the
[Uniform Resources (UR)](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-005-ur.md)
protocol over [CBOR](https://www.rfc-editor.org/rfc/rfc8949.html).

The protocol is **compatible with the Keystone / Blockchain Commons UR standard**, so
you can reuse existing open-source SDKs and only handle a small set of device-specific
details (see [§5 Device specifics](#5-device-specifics-vs-the-keystone-standard)).

**Scope.** [§4](#4-per-chain-signing) carries full walkthroughs for the four foundational
families — EVM, Bitcoin, Solana and Tron. The remaining families (TON, Cardano, Sui,
Cosmos, XRP, Bitcoin Cash and the Litecoin / Dogecoin / Dash PSBT variants) are covered by
the reference tables in [§7](#7-reference-tables) plus the per-chain guides shipped with
the `@hwlt/era-connect` SDK. The SDK implements and tests all eleven families.

---

## Table of contents

0. [Quickstart](#0-quickstart)
1. [Foundations: UR, CBOR and animated QR](#1-foundations-ur-cbor-and-animated-qr)
2. [Linking: importing accounts](#2-linking-importing-accounts)
3. [The signing model](#3-the-signing-model)
4. [Per-chain signing](#4-per-chain-signing)
   - [4.1 EVM](#41-evm-ethereum-and-evm-compatible-chains)
   - [4.2 Bitcoin](#42-bitcoin)
   - [4.3 Solana](#43-solana)
   - [4.4 Tron](#44-tron)
5. [Device specifics vs the Keystone standard](#5-device-specifics-vs-the-keystone-standard)
6. [Optional: backing a WalletConnect wallet](#6-optional-backing-a-walletconnect-wallet)
7. [Reference tables](#7-reference-tables)
8. [Recommended libraries](#8-recommended-libraries)
9. [Security & gotchas](#9-security--gotchas)
10. [Standards & links](#10-standards--links)

---

## 0. Quickstart

Integration is four steps:

1. **Link** — the user displays a `crypto-multi-accounts` animated QR on the device; you
   scan it, decode the extended public keys, and derive addresses. → [§2](#2-linking-importing-accounts)
2. **Build a request** — construct a chain-specific `*-sign-request` UR carrying the raw
   payload to sign and the derivation path. → [§4](#4-per-chain-signing)
3. **Show the animated QR** — render the request UR as an animated QR for the device to
   scan. The user reviews and approves **on the device**. → [§1.3](#13-animated-qr-fountain-encoding)
4. **Scan the signature** — the device shows a `*-signature` animated QR; you scan it,
   extract the signature, assemble the final transaction and broadcast it with your own
   infrastructure. → [§4](#4-per-chain-signing)

```
┌────────────────┐   crypto-multi-accounts (QR)   ┌──────────────────┐
│                │ ◀───────────────────────────── │                  │
│  Software      │                                 │  ERA hardware    │
│  wallet        │   *-sign-request (animated QR)  │  wallet          │
│  (your app)    │ ─────────────────────────────▶ │  (air-gapped)    │
│                │                                 │  user approves   │
│                │   *-signature (animated QR)     │  on device       │
│                │ ◀───────────────────────────── │                  │
└────────────────┘                                 └──────────────────┘
```

**Supported chains**

This guide documents **EVM chains** (Ethereum and all EVM-compatible networks),
**Bitcoin**, **Solana** and **Tron**:

| Chain | Sign tx | Sign message |
|---|---|---|
| EVM (Ethereum + all EVM chains) | ✅ `eth-sign-request` | ✅ personal_sign / EIP-712 |
| Bitcoin | ✅ `crypto-psbt` (PSBT v0) | ✅ BIP-44 / 49 / 84 on firmware 2.1.0+, legacy P2PKH on older (see [§5](#5-device-specifics-vs-the-keystone-standard)) |
| Solana | ✅ `sol-sign-request` | ✅ |
| Tron | ✅ `keystone-sign-request` | ⚠️ UTF-8 bytes in the same `keystone-sign-request` `rawData` (no separate message type) |

> The four families above are the ones this guide walks through end to end. The device
> also signs for TON, Cardano, Sui, Cosmos, XRP, Bitcoin Cash and the Litecoin / Dogecoin /
> Dash PSBT variants: their wire types and derivation paths are in
> [§7 Reference tables](#7-reference-tables), and `@hwlt/era-connect` implements and tests
> all eleven.

You only need a CBOR codec, a UR codec, an animated-QR encoder/decoder and a camera.
Everything else is standard chain tooling (RLP, PSBT, Solana message, Tron protobuf).
See [§8 Recommended libraries](#8-recommended-libraries).

---

## 1. Foundations: UR, CBOR and animated QR

### 1.1 Uniform Resources (UR)

A **UR** is a URI-encoded, self-describing CBOR payload. The single-part form is:

```
ur:<type>/<bytewords-payload>
```

- `<type>` — the registry type, e.g. `eth-sign-request`. On the wire it is rendered
  **uppercase** (`UR:ETH-SIGN-REQUEST/...`); parsing is case-insensitive.
- `<bytewords-payload>` — the CBOR bytes encoded with
  [Bytewords](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-012-bytewords.md)
  (minimal style) plus a CRC32 checksum.

When the payload is too large for one QR, it is split into a **multi-part** sequence:

```
ur:<type>/<seqNum>-<seqLen>/<fragment-bytewords>
```

See the spec: [BCR-2020-005 (UR)](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-005-ur.md)
and [BCR-2020-006 (UR Registry)](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-006-urtypes.md).

> **Registry tags vs. UR type strings.** Each registry structure has both a *type string*
> (used in `ur:<type>/...`) and a *numeric CBOR tag* (e.g. `eth-sign-request` ↔ tag `401`).
> As a **top-level UR**, the structure is identified by the **type string** and the CBOR
> map is **untagged**. The numeric tag only appears when the structure is embedded inside
> another CBOR object. Decoders therefore dispatch on the UR type string, then read a bare
> CBOR map. (Nested helpers such as `crypto-keypath` are still tagged — see §1.4.)

### 1.2 CBOR conventions

All ERA payloads are CBOR maps with **integer keys** (not strings). You will work with:

| CBOR type | Used for |
|---|---|
| byte string | UUIDs, signatures, public keys, raw tx/message bytes, PSBT |
| text string | origin, device/wallet name, addresses (BTC), note JSON |
| unsigned int | chainId, dataType, signType, version, fingerprint |
| boolean | hardened-path flags |
| array | derivation path components, address/keypath lists |
| map | the envelope itself, and the nested `crypto-keypath` |

**CBOR tags you will encounter:**

| Tag | Meaning | Reference |
|---|---|---|
| `37` | UUID | [RFC 8949 §3.4](https://www.rfc-editor.org/rfc/rfc8949.html#name-bytes), [RFC 9562](https://www.rfc-editor.org/rfc/rfc9562.html) |
| `304` | `crypto-keypath` (derivation path) | [BCR-2020-007](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-007-hdkey.md) |
| `303` | `crypto-hdkey` | [BCR-2020-007](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-007-hdkey.md) |
| `310` | `crypto-psbt` | [BCR-2020-006](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-006-urtypes.md) |
| `1103` | `crypto-multi-accounts` | [Keystone registry](https://github.com/KeystoneHQ/keystone-airgaped-base) |

CBOR reference: [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949.html) · [cbor.io](https://cbor.io/).

### 1.3 Animated QR (fountain encoding)

Multi-part URs use a **fountain code** (a Luby-transform / rateless code): each emitted
fragment is the XOR of a pseudo-random subset of the source fragments. This makes the
animation **loss-tolerant** — the receiver does not need to capture frames in order, it
just keeps reading until it has enough independent fragments to reconstruct the payload.

Practical guidance:

- **Encoding (your → device):** partition the CBOR payload into fragments, then loop
  emitting `ur.next()` frames. A single-part payload yields the plain `ur:<type>/...`
  form. Animate at **~5–10 frames/second** (≈100–200 ms/frame) and keep each fragment
  within a QR version that scans reliably at typical phone distances.
- **Decoding (device → your):** feed every scanned frame into the decoder, **deduplicate**
  identical frames, and stop when the decoder reports completion. Show progress as
  `receivedParts / expectedParts`.

Reference reading: [Fountain code](https://en.wikipedia.org/wiki/Fountain_code) ·
[Luby transform code](https://en.wikipedia.org/wiki/Luby_transform_code) ·
the multi-part UR section of [BCR-2020-005](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-005-ur.md#multi-part-urs).

**Decode an animated UR (camera → CBOR bytes):**

```dart
// Dart — using a UR codec (e.g. the `ur` / `cbor` packages)
final decoder = URDecoder();
final seen = <String>{};

void onQrFrame(String text) {
  if (!seen.add(text)) return;        // dedup identical frames
  decoder.receivePart(text);          // feed the fountain decoder
  progress.value = decoder.estimatedPercentComplete;
  if (decoder.isComplete) {
    final ur = decoder.resultUR();    // { type, cbor: Uint8List }
    handleUr(ur.type, ur.cborBytes);
  }
}
```

```kotlin
// Kotlin — using sparrowwallet/hummingbird (BC-UR)
import com.sparrowwallet.hummingbird.URDecoder

val decoder = URDecoder()
val seen = HashSet<String>()

fun onQrFrame(text: String) {
    if (!seen.add(text)) return                 // dedup
    decoder.receivePart(text)                   // feed
    val r = decoder.result
    if (r != null && r.type == URDecoder.Result.Type.SUCCESS) {
        val ur = r.ur                           // ur.type, ur.cborBytes()
        handleUr(ur.type, ur.toBytes())
    }
}
```

```swift
// Swift — using BlockchainCommons/URKit
import URKit

var decoder = URDecoder()
var seen = Set<String>()

func onQrFrame(_ text: String) {
    guard seen.insert(text).inserted else { return }   // dedup
    decoder.receivePart(text)                            // feed
    switch decoder.result {
    case .success(let ur):
        handleUr(ur.type, try! CBOR(ur.cbor))           // ur.type, ur.cbor (bytes)
    case .failure, .none:
        break
    }
}
```

```typescript
// TypeScript — using @ngraveio/bc-ur
import { URDecoder } from '@ngraveio/bc-ur';

const decoder = new URDecoder();
const seen = new Set<string>();

function onQrFrame(text: string) {
  if (seen.has(text)) return;          // dedup
  seen.add(text);
  decoder.receivePart(text);           // feed
  if (decoder.isComplete() && decoder.isSuccess()) {
    const ur = decoder.resultUR();     // ur.type, ur.cbor (Buffer)
    handleUr(ur.type, ur.cbor);
  }
}
```

**Encode CBOR bytes → animated UR frames (your → camera):**

```dart
// Dart
final ur = UR.fromCbor(type: 'eth-sign-request', cbor: cborBytes);
final encoder = UREncoder(ur, maxFragmentLength: 180);
Timer.periodic(const Duration(milliseconds: 125), (_) {
  qrData.value = encoder.nextPart();   // drive a QR widget with this string
});
```

```kotlin
// Kotlin — hummingbird
import com.sparrowwallet.hummingbird.UR
import com.sparrowwallet.hummingbird.UREncoder

val ur = UR("eth-sign-request", cborBytes)
val encoder = UREncoder(ur, /* maxFragmentLen */ 180, /* firstSeqNum */ 0)
// every ~125ms:
val frame: String = encoder.nextPart()   // render `frame` as a QR
```

```swift
// Swift — URKit
import URKit

let ur = try! UR(type: "eth-sign-request", cbor: cborBytes)
var encoder = UREncoder(ur, maxFragmentLen: 180)
// every ~125ms:
let frame = encoder.nextPart()           // render `frame` as a QR
```

```typescript
// TypeScript — @ngraveio/bc-ur
import { UR, UREncoder } from '@ngraveio/bc-ur';

const ur = new UR(Buffer.from(cborBytes), 'eth-sign-request');
const encoder = new UREncoder(ur, /* maxFragmentLength */ 180);
setInterval(() => {
  const frame = encoder.nextPart();      // render `frame` as a QR (uppercase)
}, 125);
```

### 1.4 `crypto-keypath` (tag 304)

Derivation paths are encoded as a tagged map. Key `1` is a **flat array** alternating
`[childIndex, hardened?]`; key `2` is the source/parent fingerprint (a `uint`).

`m/44'/60'/0'/0/5` becomes:

```
304({
  1: [44, true, 60, true, 0, true, 0, false, 5, false],
  2: <fingerprint>
})
```

i.e. each path element is two array entries: the index, then a boolean that is `true`
for hardened (`'`) levels. See [BCR-2020-007](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-007-hdkey.md).

---

## 2. Linking: importing accounts

The user puts the device into its "connect / sync" mode; it displays an animated QR of
type **`crypto-multi-accounts`** (Keystone registry, CBOR tag `1103`). Decode it to get
the device's account-level extended public keys for every chain. You then derive
addresses **locally** — the device is not needed again until signing.

Reference: [Keystone `crypto-multi-accounts`](https://github.com/KeystoneHQ/keystone-airgaped-base/tree/master/packages/ur-registry-crypto-multi-accounts).

### 2.1 `crypto-multi-accounts` structure

Top-level CBOR map:

| Key | Type | Meaning |
|---|---|---|
| `1` | uint | master fingerprint (XFP) |
| `2` | array | list of account entries (each a `crypto-hdkey`, see below) |
| `3` | text | device label |
| `4` | text | device id |
| `5` | text | device / firmware version |

Each **account entry** is a `crypto-hdkey` CBOR map:

| Key | Type | Meaning |
|---|---|---|
| `1` | bool | `true` if this is the master key (usually absent/false for accounts) |
| `2` | bool | `false` (public key, not private) |
| `3` | bytes | public key — 33-byte compressed secp256k1, **or** 32-byte Ed25519 |
| `4` | bytes | chain code (32 bytes) |
| `5` | `crypto-coin-info` | optional coin/network info |
| `6` | `crypto-keypath` (tag 304) | the account derivation path + parent fingerprint |
| `8` | uint | parent fingerprint |
| `9` | text | account name |
| `10` | text | note — a label string (e.g. `account.standard`) |

> **Identify the chain by the derivation path (key 6), not the note.** The `note` field is
> a plain label (`account.standard` / `account.ledger_live` / …), not chain metadata. Match
> the keypath prefix instead — `44'/60'` → EVM, `84'/0'` (also `44'`/`49'`/`86'`) → Bitcoin,
> `44'/501'` → Solana, `44'/195'` → Tron, and see [§7.3](#73-derivation-paths--slip-44) for
> the rest. An export whose prefix you do not recognise is still usable: it carries its path,
> fingerprint and public key, so pass it through rather than dropping it.

The four families this guide walks through, and their account-level paths — every other
family the device exports is in [§7.3](#73-derivation-paths--slip-44):

| Chain | Account path | Key material | Address from |
|---|---|---|---|
| Bitcoin | `m/84'/0'/0'` (BIP-84) | secp256k1 xpub + chain code | BIP32 child `0/idx` (receive), `1/idx` (change) → bech32 |
| EVM | `m/44'/60'/0'` | secp256k1 xpub + chain code | BIP32 child `0/idx` → keccak256 → last 20 bytes |
| Tron | `m/44'/195'/0'` | secp256k1 xpub + chain code | BIP32 child `0/idx` → keccak256 → last 20 → `0x41` + base58check |
| Solana | `m/44'/501'/0'` … `m/44'/501'/9'` | Ed25519 public key (+ chain code) | the public key **is** the address (base58); no child derivation |

Coin types follow [SLIP-44](https://github.com/satoshilabs/slips/blob/master/slip-0044.md):
BTC=`0`, ETH=`60`, Tron=`195`, Solana=`501`.

> **Solana is special.** Ed25519 does not support public BIP32 derivation, so the device
> pre-derives a fixed set of accounts (`m/44'/501'/0'` … `m/44'/501'/9'`), each exported
> as its own entry. The "account index" you pick is the third (hardened) path level.
> A chain code is included in the entry, but you do **not** derive children — the exported
> key already *is* the signing key, and its raw bytes (base58) are the address.

> **Bitcoin is wallet-level.** From the single `m/84'/0'/0'` account xpub you derive the
> whole address window yourself (`0/0..n` receive, `1/0..n` change). Use a
> [BIP-44 gap limit](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki#address-gap-limit)
> (e.g. 20) when scanning for funds. You can also reconstruct a `zpub`
> ([SLIP-132](https://github.com/satoshilabs/slips/blob/master/slip-0132.md), version
> bytes `0x04b24746`) for tools that aggregate over the whole HD wallet.

**Store the raw UR string** of the linked accounts; re-decode it whenever you need to
derive more addresses.

### 2.2 Example: decode accounts and derive an EVM address

```dart
// Dart — cbor + bip32 (e.g. `cbor`, `bip32`, `pointycastle`/keccak)
final map = cbor.decode(multiAccountsCborBytes) as Map;
final accounts = map[2] as List;

// pick the EVM account: keypath starts with 44'/60'/0'
final evm = accounts.firstWhere((a) {
  final path = ((a as Map)[6] as Map)[1] as List; // crypto-keypath key 1
  return path[0] == 44 && path[2] == 60;
});
final pub = Uint8List.fromList((evm[3] as List).cast<int>());      // 33-byte compressed
final chainCode = Uint8List.fromList((evm[4] as List).cast<int>()); // 32-byte

final node = BIP32.fromPublicKey(pub, chainCode);
final child = node.derivePath('0/0');                 // receive index 0
final uncompressed = decompressSecp256k1(child.publicKey); // 65 bytes, strip 0x04
final addr = '0x' + hex.encode(keccak256(uncompressed.sublist(1)).sublist(12));
```

```kotlin
// Kotlin — kethereum + a BIP32 lib (e.g. KEthereum bip32 / NovaCrypto BIP32)
val map = CBORMapper().readValue(multiAccountsCborBytes, Map::class.java)
val accounts = map[2] as List<Map<Int, Any>>

val evm = accounts.first {
    val path = ((it[6] as Map<Int, Any>)[1] as List<Any>)
    path[0] == 44 && path[2] == 60
}
val pub = evm[3] as ByteArray            // 33-byte compressed
val chainCode = evm[4] as ByteArray      // 32-byte

val node = ExtendedPublicKey(pub, chainCode)
val child = node.derive("0/0")
val uncompressed = decompress(child.publicKey)        // 65 bytes
val hash = Keccak256().digest(uncompressed.copyOfRange(1, 65))
val addr = "0x" + hash.copyOfRange(12, 32).toHexString()
```

```swift
// Swift — WalletCore or a BIP32 lib + Keccak
let map = try CBOR.decode(Array(multiAccountsCbor))!
guard case let .array(accounts)? = map[2] else { fatalError() }

let evm = accounts.first {
    if case let .map(m) = $0, case let .map(kp)? = m[6],
       case let .array(path)? = kp[1],
       case let .unsignedInt(p0)? = path[0], case let .unsignedInt(p2)? = path[2] {
        return p0 == 44 && p2 == 60
    }
    return false
}!
// extract pub (key 3) and chainCode (key 4) as Data, then:
let node = PublicKey(data: pub, type: .secp256k1)!
let child = deriveChild(node, path: "0/0")              // via your BIP32 lib
let uncompressed = child.uncompressed.data             // 65 bytes
let addr = "0x" + Hash.keccak256(data: uncompressed.dropFirst()).suffix(20).hexString
```

```typescript
// TypeScript — @keystonehq/bc-ur-registry-crypto-multi-accounts + @scure/bip32 + viem
import { CryptoMultiAccounts } from '@keystonehq/bc-ur-registry';
import { HDKey } from '@scure/bip32';
import { publicKeyToAddress } from 'viem/utils';

const accounts = CryptoMultiAccounts.fromCBOR(Buffer.from(cborBytes));
const evm = accounts.getKeys().find(k =>
  k.getOrigin()?.getPath()?.startsWith("44'/60'/0'"));

const node = HDKey.fromExtendedKey(/* or build from */ {
  publicKey: evm.getKey(),        // 33-byte compressed
  chainCode: evm.getChainCode(),  // 32-byte
});
const child = node.derive('m/0/0');               // receive index 0
const address = publicKeyToAddress(`0x${Buffer.from(child.publicKey).toString('hex')}`);
```

For Bitcoin, derive `child = node.derive('m/0/<idx>')` and encode a
[bech32](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki) P2WPKH address
(witness v0, hash160 of the compressed pubkey). For Solana, the entry's key bytes
(`evm[3]` equivalent) base58-encoded **are** the address.

---

## 3. The signing model

Every signing operation follows the same loop:

1. **Build** a chain-specific request UR. On most chains it carries a `requestId` (a UUID),
   the raw payload in `signData`, the `crypto-keypath` to sign with, and the expected signer
   address (where applicable). Bitcoin PSBT and XRP carry no request id at all — for those the
   binding is the returned content itself (see [§5](#5-device-specifics-vs-the-keystone-standard)).
2. **Display** it as an animated QR.
3. The user **reviews and approves on the device**. The device parses the payload and
   shows the human-readable details on its own screen. *The device is the security
   boundary* — your app does not need to (and cannot) approve on the user's behalf.
4. The device returns a **signature UR**, animated. You scan it, match it by `requestId`,
   extract the signature, assemble the final transaction and broadcast it yourself.

There are two ways to drive step 1:

- **You build the transaction** (the typical wallet flow): you construct the unsigned tx
  (RLP / PSBT / Solana message / Tron raw_data) and put the *exact bytes that must be
  signed* into `signData`.
- **You forward a raw payload** (the WalletConnect "conduit" flow): a dApp hands you a
  ready transaction or message; you wrap its raw bytes verbatim and let the device parse
  and decide what it can sign. See [§6](#6-optional-backing-a-walletconnect-wallet).

Where a `requestId` exists it lets you correlate responses and reject stale or mismatched
signatures; on the two chains without one, compare the returned transaction against what you
sent instead.
Generate a fresh [UUID](https://www.rfc-editor.org/rfc/rfc9562.html) per request.

---

## 4. Per-chain signing

Each subsection gives the request UR, the exact CBOR map, what goes into `signData`, the
response UR, and how to assemble the result. Replace `idx` with the address index of the
account you linked in [§2](#2-linking-importing-accounts).

The four subsections below are the foundational families and are walked through in full.
TON, Cardano, Sui, Cosmos, XRP, Bitcoin Cash and the Litecoin / Dogecoin / Dash PSBT
variants are **not** walked through here: their UR types, `dataType` values and derivation
paths are in [§7](#7-reference-tables), and the worked examples live in the per-chain
guides shipped with the `@hwlt/era-connect` SDK. All eleven families are implemented and
tested by that SDK.

### 4.1 EVM (Ethereum and EVM-compatible chains)

**Request — `eth-sign-request`** (Keystone tag `401`,
[`@keystonehq/bc-ur-registry-eth`](https://www.npmjs.com/package/@keystonehq/bc-ur-registry-eth)):

| Key | Type | Meaning |
|---|---|---|
| `1` | bytes | `requestId` — 16-byte UUID, a **bare** byte string on this chain (see [§5](#5-device-specifics-vs-the-keystone-standard)) |
| `2` | bytes | `signData` — RLP tx, or raw message bytes |
| `3` | uint | `dataType` (see below) |
| `4` | uint | `chainId` |
| `5` | `crypto-keypath` (tag 304) | `m/44'/60'/0'/0/idx` + fingerprint |
| `6` | bytes | signer address (20 bytes) |
| `7` | text | `origin` (free-form label) |

**`dataType` values:**

| Value | Meaning | `signData` contents |
|---|---|---|
| `1` | transaction | the RLP-encoded tx (see below) |
| `2` | EIP-712 typed data | the typed-data JSON (UTF-8 bytes) |
| `3` | `personal_sign` / raw bytes | the raw message bytes (EIP-191 prefix applied by the device) |
| `4` | typed transaction | the typed-tx bytes (same as `1`) |

> For transactions use `dataType = 1` (or `4` — the device treats them the same). The
> device infers EIP-1559 (`0x02…`), EIP-2930 (`0x01…`) or legacy (`0xC0…`) from the RLP
> **type-prefix byte**, so you do not signal the tx type via `dataType`.

**`signData` for a transaction:**

- **EIP-1559** ([EIP-1559](https://eips.ethereum.org/EIPS/eip-1559) /
  [EIP-2718](https://eips.ethereum.org/EIPS/eip-2718)):
  `0x02 || RLP([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList])`
- **Legacy** ([EIP-155](https://eips.ethereum.org/EIPS/eip-155)):
  `RLP([nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0])`

> **Field order matters.** For EIP-1559 the order is
> `[chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList]`.
> A missing `nonce` silently shifts every later field and the broadcast will be rejected.

**Response — `eth-signature`** (tag `402`):

| Key | Type | Meaning |
|---|---|---|
| `1` | bytes | `requestId` (echoes the request UUID) |
| `2` | bytes | signature = `r (32) ‖ s (32) ‖ v` |

The device computes `v` for you:

- **EIP-1559 / EIP-2930 transactions and messages** → `v` is the recovery parity (`0`/`1`),
  so the signature is **65 bytes**.
- **Legacy EIP-155 transactions** → `v` is already `parity + chainId·2 + 35`, which for a
  large `chainId` can be more than one byte (signature **> 65 bytes**).

Assemble the result:

- **Messages** (`personal_sign` / EIP-712): if the dApp expects `27`/`28`, map parity
  `0`/`1` → `27`/`28`; return `0x` + hex(r‖s‖v).
- **EIP-1559 tx:** `0x02 || RLP([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList, v, r, s])` with `v` = the returned parity.
- **Legacy tx:** `RLP([nonce, gasPrice, gasLimit, to, value, data, v, r, s])` using the
  returned `v` **as-is** (it is already EIP-155-encoded — do not re-apply the formula).

**Build the request:**

```dart
// Dart
final cborMap = {
  1: CborBytes(uuidBytes),                       // requestId (untagged)
  2: CborBytes(signData),                         // 0x02||RLP(...) for EIP-1559
  3: CborSmallInt(1),                             // dataType: 1 = transaction
  4: CborSmallInt(chainId),
  5: CborMap({
       1: CborList([44, true, 60, true, 0, true, 0, false, idx, false]
              .map(_toCbor).toList()),
       2: CborSmallInt(masterFingerprint),
     }, tags: [304]),
  6: CborBytes(hex.decode(address.substring(2))), // 20 bytes
  7: CborString('My Wallet'),
};
final ur = UR.fromCbor(type: 'eth-sign-request', cbor: cbor.encode(CborMap(cborMap)));
```

```kotlin
// Kotlin — @keystonehq/bc-ur-registry-eth (Android) or hand-rolled CBOR
import com.keystone.sdk.* // or build the CBOR map directly
val req = EthSignRequest.constructETHRequest(
    signData,                       // 0x02||RLP(...)
    DataType.TRANSACTION,           // -> CBOR dataType = 1
    "44'/60'/0'/0/$idx",
    xfpHex,                         // master fingerprint hex
    UUID.randomUUID().toString(),
    chainId,
    address,                        // 0x...
    "My Wallet"
)
val ur = req.toUR()                 // type "eth-sign-request"
```

```swift
// Swift — KeystoneSDK (iOS) or URKit + a CBOR encoder
import KeystoneSDK
let evm = EthSignRequest(
    requestId: UUID().uuidString,
    signData: signDataHex,          // 0x02||RLP(...)
    dataType: .transaction,         // -> 1
    chain: .ethereum,
    path: "m/44'/60'/0'/0/\(idx)",
    xfp: xfpHex,
    address: address,
    origin: "My Wallet"
)
let ur = try KeystoneSDK().eth.generateSignRequest(ethSignRequest: evm) // UREncoder
```

```typescript
// TypeScript — @keystonehq/bc-ur-registry-eth
import { EthSignRequest, DataType } from '@keystonehq/bc-ur-registry-eth';
import { v4 as uuidv4 } from 'uuid';

const req = EthSignRequest.constructETHRequest(
  signData,                  // Buffer: 0x02||RLP(...)
  DataType.transaction,      // -> dataType 1
  `44'/60'/0'/0/${idx}`,
  xfpHex,                    // master fingerprint hex
  uuidv4(),
  chainId,
  address,                   // 0x...
  'My Wallet',
);
const ur = req.toUREncoder(/* maxFragmentLength */ 180); // drive the animated QR
```

**Parse the response and assemble a signed EIP-1559 tx:**

```dart
// Dart
final map = cbor.decode(signatureCborBytes) as Map;
final sig = Uint8List.fromList((map[2] as List).cast<int>()); // 65 bytes
final r = sig.sublist(0, 32), s = sig.sublist(32, 64);
final v = sig[64];                                            // parity 0/1
final signed = Uint8List.fromList([0x02, ...rlpEncode([
  chainId, nonce, maxPriorityFee, maxFee, gasLimit, to, value, data, [], v, r, s,
])]);
final rawTxHex = '0x${hex.encode(signed)}';                   // broadcast this
```

```kotlin
// Kotlin
val map = CBORMapper().readValue(signatureCbor, Map::class.java)
val sig = map[2] as ByteArray                  // 65 bytes
val r = sig.copyOfRange(0, 32); val s = sig.copyOfRange(32, 64); val v = sig[64].toInt()
val signed = byteArrayOf(0x02) + RlpEncoder.encode(
    RlpList(/* chainId, nonce, ... , accessList */, RlpInt(v), RlpBytes(r), RlpBytes(s)))
val rawTxHex = "0x" + signed.toHexString()
```

```swift
// Swift
let map = try CBOR.decode(Array(signatureCbor))!
guard case let .byteString(sig)? = map[2] else { return }   // 65 bytes
let r = Array(sig[0..<32]); let s = Array(sig[32..<64]); let v = Int(sig[64])
let signed = [0x02] + RLP.encode([chainId, nonce, /* ... */, accessList, v, r, s])
let rawTxHex = "0x" + Data(signed).hexString
```

```typescript
// TypeScript — viem/ethers
import { ETHSignature } from '@keystonehq/bc-ur-registry-eth';
import { serializeTransaction } from 'viem';

const sigUR = ETHSignature.fromCBOR(signatureCbor);
const sig = sigUR.getSignature();              // 65 bytes
const r = `0x${sig.subarray(0, 32).toString('hex')}`;
const s = `0x${sig.subarray(32, 64).toString('hex')}`;
const yParity = sig[64] & 1;
const rawTx = serializeTransaction(
  { chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gas: gasLimit, to, value, data },
  { r, s, yParity },
);                                              // broadcast this
```

### 4.2 Bitcoin

Bitcoin transactions are signed as **PSBT** ([BIP-174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki)).

> **Use PSBT v0.** The device's signer relies on the global `UNSIGNED_TX` field that PSBT
> **version 0** (BIP-174) carries; PSBT v2
> ([BIP-370](https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki)) drops it, and
> older firmware can fail on v2 — emit v0. Each input must carry its BIP32 derivation, plus
> `witnessUtxo` (segwit), `redeemScript` (nested segwit) or `nonWitnessUtxo` (legacy).

**Request — `crypto-psbt`** (tag `310`,
[BCR-2020-006](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-006-urtypes.md)):
the UR payload is a **bare CBOR byte string** of the raw PSBT — *not* a map.

**Response — `crypto-psbt`:** the device returns a **bare CBOR byte string** containing
the **signed but NOT finalized** PSBT. You finalize it yourself and broadcast (or hand
the signed PSBT base64 back to a dApp for `signPsbt`).

```dart
// Dart — build request
final ur = UR.fromCbor(
  type: 'crypto-psbt',
  cbor: cbor.encode(CborBytes(psbtBytes)),   // raw PSBT v0 bytes
);

// parse response
final signedPsbt = cbor.decode(responseCborBytes) as CborBytes; // bare byte string
final finalTx = finalizeAndExtract(signedPsbt.bytes);           // via bitcoin lib
final rawTxHex = hex.encode(finalTx);
```

```kotlin
// Kotlin — hummingbird + bitcoinj
import com.sparrowwallet.hummingbird.registry.CryptoPSBT

val ur = CryptoPSBT(psbtBytes).toUR()          // type "crypto-psbt"

// response
val signed = CryptoPSBT.fromCbor(responseCbor).psbt   // signed, not finalized
val tx = PSBT.fromBytes(signed).finalizeAndExtract()  // via your BTC lib
val rawTxHex = tx.bitcoinSerialize().toHexString()
```

```swift
// Swift — URKit + a PSBT lib (e.g. LibWally / WalletCore)
let ur = try UR(type: "crypto-psbt", cbor: CBOR.byteString(Array(psbtBytes)).encode())

// response
guard let signed = try? CBOR.decode(Array(responseCbor)),
      case let .byteString(bytes) = signed else { return }
let tx = try PSBT(psbt: Data(bytes)).finalizedTransaction()  // via your BTC lib
let rawTxHex = tx.serialized.hexString
```

```typescript
// TypeScript — @keystonehq/bc-ur-registry + bitcoinjs-lib
import { CryptoPSBT } from '@keystonehq/bc-ur-registry';
import { Psbt } from 'bitcoinjs-lib';

const ur = new CryptoPSBT(psbtBuffer).toUREncoder(180);  // animate

// response
const signed = CryptoPSBT.fromCBOR(responseCbor).getPSBT();
const psbt = Psbt.fromBuffer(signed);
psbt.finalizeAllInputs();
const rawTxHex = psbt.extractTransaction().toHex();      // broadcast this
```

**Bitcoin message signing — `btc-sign-request`** (tag `8101`,
[`@keystonehq/bc-ur-registry-btc`](https://www.npmjs.com/package/@keystonehq/bc-ur-registry-btc)):

| Key | Type | Meaning |
|---|---|---|
| `1` | bytes | `requestId` — UUID, **tag-37-wrapped** on this chain (see [§5](#5-device-specifics-vs-the-keystone-standard)) |
| `2` | bytes | the message bytes |
| `3` | uint | `dataType` = `1` (message) |
| `4` | array | `[ crypto-keypath ]` — `m/84'/0'/0'/0/idx` |
| `5` | array | `[ address ]` — the address string |
| `6` | text | `origin` |

Response — `btc-signature` (tag `8102`): map `{1: requestId, 2: signature}`, a
[BIP-137](https://github.com/bitcoin/bips/blob/master/bip-0137.mediawiki) message
signature. Firmware **2.1.0+** puts the **raw 65 bytes** (header ‖ r ‖ s) in key `2`;
older firmware puts the **ASCII of its base64** there. Accept both, and hand dApps the
base64 form.

> **Address kinds depend on the firmware generation.** Firmware **2.1.0+** signs
> BIP-44 (`1...`), BIP-49 (`3...`) and BIP-84 (`bc1q...`) with the matching BIP-137
> header and refuses only Taproot (`bc1p...`) — BIP-137 has no header range for it;
> `xfp` is required. **Older firmware** signs legacy P2PKH only. Either way the refusal
> is an **empty** signature in key `2` — detect it and surface a clear error.

### 4.3 Solana

**Request — `sol-sign-request`** (Keystone tag `1101`,
[`@keystonehq/bc-ur-registry-sol`](https://www.npmjs.com/package/@keystonehq/bc-ur-registry-sol)):

| Key | Type | Meaning |
|---|---|---|
| `1` | bytes | `requestId` — UUID, a **bare** byte string on this chain (see [§5](#5-device-specifics-vs-the-keystone-standard)) |
| `2` | bytes | `signData` — the serialized Solana **message** (or raw message bytes) |
| `3` | `crypto-keypath` (tag 304) | `m/44'/501'/idx'` + fingerprint |
| `4` | bytes | signer Ed25519 public key (32 bytes) |
| `5` | text | `origin` |
| `6` | uint | `version` = `1` |
| `7` | uint | `signType` — **message only**: `2` = off-chain message (omit for tx) |

`signData` for a transaction is the **compiled message** bytes
([`@solana/web3.js`](https://solana-labs.github.io/solana-web3.js/) `Message`/
`VersionedMessage`). The device signs the bytes **verbatim** (no off-chain prefix).

> Note the path is the 3-level hardened account path `m/44'/501'/idx'` (matching what the
> device exported in §2), **not** a 5-level path.

**Response — `sol-signature`** (tag `1102`): map `{1: requestId, 2: signature}` where
signature is the **64-byte** Ed25519 signature.

- **For a transaction:** attach the signature to the message to form a signed tx, then
  broadcast (base64).
- **For sign-only / messages:** return the signature **base58**-encoded.

```dart
// Dart — build request
final cborMap = {
  1: CborBytes(uuidBytes),
  2: CborBytes(messageBytes),                  // compiled Solana message
  3: CborMap({
       1: CborList([44, true, 501, true, idx, true].map(_toCbor).toList()),
       2: CborSmallInt(masterFingerprint),
     }, tags: [304]),
  4: CborBytes(ed25519PubKey),                 // 32 bytes
  5: CborString('My Wallet'),
  6: CborSmallInt(1),                          // version
};
final ur = UR.fromCbor(type: 'sol-sign-request', cbor: cbor.encode(CborMap(cborMap)));

// parse response
final sig = Uint8List.fromList(((cbor.decode(resp) as Map)[2] as List).cast<int>()); // 64
```

```typescript
// TypeScript — @keystonehq/bc-ur-registry-sol + @solana/web3.js
import { SolSignRequest, SignType, SolSignature } from '@keystonehq/bc-ur-registry-sol';
import { VersionedTransaction } from '@solana/web3.js';

const req = SolSignRequest.constructSOLRequest(
  Buffer.from(messageBytes),       // compiled message
  `44'/501'/${idx}'`,
  xfpHex,
  uuidv4(),
  SignType.Transaction,            // off-chain message => SignType.Message
  ed25519Address,                  // base58
  'My Wallet',
);
const ur = req.toUREncoder(180);

// response
const sig = SolSignature.fromCBOR(resp).getSignature();   // 64 bytes
tx.addSignature(new PublicKey(ed25519Address), sig);
const raw = Buffer.from(tx.serialize()).toString('base64');
```

```kotlin
// Kotlin — hummingbird / Keystone Android SDK
val req = SolSignRequest.constructSOLRequest(
    messageBytes, "44'/501'/$idx'", xfpHex, UUID.randomUUID().toString(),
    SignType.TRANSACTION, ed25519Address, "My Wallet")
val ur = req.toUR()

// response
val sig = SolSignature.fromCbor(resp).signature      // 64 bytes
```

```swift
// Swift — KeystoneSDK
let req = SolSignRequest(
    requestId: UUID().uuidString, signData: messageHex,
    path: "m/44'/501'/\(idx)'", xfp: xfpHex,
    signType: .transaction, address: ed25519Address, origin: "My Wallet")
let ur = try KeystoneSDK().sol.generateSignRequest(solSignRequest: req)
// response: SolSignature.signature -> 64 bytes
```

### 4.4 Tron

Tron signing uses a **structured, device-specific request**: a gzip-compressed protobuf wrapped
in the `keystone-sign-request` UR (tag `6101`). The chain-generic `tron-sign-request`
(tag `5101`) is reserved but **not active in current firmware**, so use the path below. It
covers **any** Tron transaction: the protobuf's `rawData` field carries the ready-made
`Transaction.raw_data` bytes (TRX/TRC-10/TRC-20 transfers, contract calls, arbitrary dApp
calldata) — the device signs `sha256(rawData) = txID`. The semantic fields
(`from`/`to`/`value`/…) drive the on-device display and may be empty.

**Request — `keystone-sign-request`** (tag `6101`). The simplest accepted shape is a
**two-key map** — the device detects the gzip magic in key `1` and decompresses it:

| Key | Type | Meaning |
|---|---|---|
| `1` | bytes | `signData` — **gzip-compressed protobuf** (gzip magic `1f 8b 08`; see below) |
| `2` | text | `origin` |

> The firmware also accepts a richer map (`{1: requestId, 2: signData, 3: crypto-keypath,
> 4: xfp, 5: tokenInfo}`) where key `1` is a UUID string and the gzip protobuf moves to key
> `2`. The two-key form above is the simplest and is what this guide uses — the
> `requestId`, `hdPath` and `xfp` it would carry already live **inside** the protobuf.

**`signData` protobuf.** Build the "QrCode Protocol" message, then gzip it. Hierarchy
`Base` → `Payload` (carries `xfp`) → `SignTransaction` (protobuf field numbers in
parentheses; `tronTx` is field **8** inside `SignTransaction`):

```
SignTransaction {
  coinCode: "TRON" (1), signId: <uuid string> (2), hdPath: "m/44'/195'/0'/0/idx" (3),
  timestamp (4), decimal (5),
  tronTx (8) {
    token (1),             // display ticker: TRC-10 id, or "TRX"/"USDT"
    contractAddress? (2),  // contract address when known (display)
    from (3), to (4), memo? (5), value (6), fee (9),   // display; may be empty
    latestBlock (7) { hash: <full 64-hex block id> (1), number (2), timestamp (3) },
    rawData (10)           // bytes: ready-made Transaction.raw_data — the signing source of truth
  }
}
```

> **`rawData` is what gets signed.** It is the serialized `Transaction.raw_data` (Tron
> network protobuf); the device signs `sha256(rawData) = txID` and must return the
> transaction with `raw_data` **unmodified** — otherwise the txID diverges from what the
> sending side (dApp/backend) computed. The semantic fields are display-only.

> Rebuilding `ref_block_bytes` / `ref_block_hash` / `expiration` from `latestBlock`
> (ref-block-hash = bytes 8–15 of the block hash; expiration = block-timestamp + 10 min)
> is the legacy path for requests **without** `rawData`; it does not run when `rawData`
> is present. Still always pass `latestBlock`: source it from a **live now-block** query
> with the **full** 64-hex block id.

The `.proto` schemas are shipped, not on request: `proto/tron/` inside the
`@hwlt/era-connect` npm package (and in the SDK repository). Tooling:
[protobuf](https://protobuf.dev/), [nanopb](https://github.com/nanopb/nanopb) (device side),
TRON [`protocol/core`](https://github.com/tronprotocol/protocol/tree/master/core).

**Response — `keystone-sign-result`** (tag `6102`): CBOR map `{1: <gzip-compressed
protobuf>}`. Gunzip and parse `Base` → `Payload` → `signTxResult`
(`SignTransactionResult { signId (1), txId (2), rawTx (3) }`): `rawTx` is the hex of the
**fully assembled, signed** Tron transaction (`raw_data` unmodified + `signature`; the raw
signature inside is `r ‖ s ‖ recovery`, 65 bytes), `txId` = `sha256(raw_data)`, `signId`
echoes the request. Broadcast `rawTx` as-is.

```typescript
// TypeScript — gzip + cbor + a UR codec; protobuf via your generated stubs
import { UR } from '@ngraveio/bc-ur';
import { encode, decode } from 'cbor';
import { gzipSync, gunzipSync } from 'zlib';

const proto = buildSignTransactionProto({ coinCode: 'TRON', signId, xfp,
  hdPath: `m/44'/195'/0'/0/${idx}`, tronTx });     // your protobuf encoder
const cborMap = new Map<number, unknown>([[1, gzipSync(proto)], [2, 'My Wallet']]);
const ur = new UR(encode(cborMap), 'keystone-sign-request');

// response: keystone-sign-result { 1: gzip(protobuf) }
const res = decode(scannedUR.cbor) as Map<number, Buffer>;
const signedTx = parseSignResultProto(gunzipSync(res.get(1)!)); // your protobuf decoder
```

```dart
// Dart — gzip + cbor + UR
final signData = GZipEncoder().encode(buildSignTransactionProto(/* ... */))!; // gzip(protobuf)
final cborMap = { 1: CborBytes(signData), 2: CborString('My Wallet') };
final ur = UR.fromCbor(type: 'keystone-sign-request', cbor: cbor.encode(CborMap(cborMap)));

// response
final res = cbor.decode(respBytes) as Map;
final proto = GZipDecoder().decodeBytes((res[1] as List).cast<int>());
final signedTx = parseSignResultProto(proto);
```

```kotlin
// Kotlin — gzip + CBOR + hummingbird
val signData = gzip(buildSignTransactionProto(/* ... */))     // gzip(protobuf)
val cbor = CBORMapper().writeValueAsBytes(mapOf(1 to signData, 2 to "My Wallet"))
val ur = UR("keystone-sign-request", cbor)

// response: keystone-sign-result { 1: gzip(protobuf) }
val res = CBORMapper().readValue(respBytes, Map::class.java)
val signedTx = parseSignResultProto(gunzip(res[1] as ByteArray))
```

```swift
// Swift — gzip + SwiftCBOR + URKit
let signData = gzip(buildSignTransactionProto(/* ... */))     // gzip(protobuf)
let cbor = CBOR.encode([1: .byteString(Array(signData)), 2: .utf8String("My Wallet")])
let ur = try UR(type: "keystone-sign-request", cbor: cbor)

// response: keystone-sign-result { 1: gzip(protobuf) }
let res = try CBOR.decode(Array(respBytes))!
let signedTx = parseSignResultProto(gunzip(Data(res[1]!.byteStringValue()!)))
```

---

## 5. Device specifics vs the Keystone standard

The device follows the Keystone UR registry with a few deviations. Match them exactly
when building requests and parsing responses:

| Area | Device behavior |
|---|---|
| `requestId` UUID | the shape is **per chain**, not a free choice. Tag-37-wrapped on the request: Bitcoin messages, Cardano, Cosmos (incl. the Ethermint `evm-sign-request`), Sui, TON. Bare byte string on the request: EVM, Solana. TON is special — the value inside tag 37 is the **ASCII bytes of the hyphenated UUID string**, not the 16 raw bytes. Tron and Bitcoin Cash carry no CBOR request id at all: the id is the `signId` string inside the protobuf. Bitcoin PSBT and XRP carry none in either direction. On **replies** the device always wraps the echo in tag 37 — parse tag-agnostically (strip the tag, compare the bytes) |
| EVM `dataType` | transactions use `1` (or `4`); EIP-1559 / EIP-2930 / legacy is detected from the leading RLP byte, not from `dataType` |
| EVM `v` (legacy) | for legacy EIP-155 txs the device returns `v` **already** EIP-155-encoded (`parity + chainId·2 + 35`); do not re-apply the formula |
| Bitcoin PSBT | `crypto-psbt` payload is a **bare CBOR byte string** (not a map); **use PSBT v0** (carries the global `UNSIGNED_TX` the signer relies on) |
| Bitcoin messages | firmware **2.1.0+** signs BIP-44 / BIP-49 / BIP-84 addresses with the matching **BIP-137** header and refuses only Taproot (BIP-137 has no header range for it); `xfp` is required, and the reply carries the **raw 65-byte** signature. **Older firmware** signs **legacy P2PKH only**, answers a segwit address with an **empty signature**, and replies with the **ASCII of a base64 string**. Accept both reply shapes |
| Tron | uses the structured gzip-protobuf `keystone-sign-request` (`6101`) → `keystone-sign-result` (`6102`); the generic `tron-sign-request` (`5101`) is **not active** in current firmware. The signed bytes are the `rawData` field (ready-made `Transaction.raw_data`, signature = `sha256(rawData)`); the response returns `raw_data` unmodified |
| UR type on the wire | rendered **uppercase** (`UR:ETH-SIGN-REQUEST/...`); parse case-insensitively |
| `origin` | a free-form label shown for context; not security-relevant |

---

## 6. Optional: backing a WalletConnect wallet

If your wallet also speaks [WalletConnect](https://docs.reown.com/) /
[WalletKit](https://docs.reown.com/walletkit/overview), the same request/response UR
types back it directly: take the dApp's raw payload, wrap it verbatim in the matching
`*-sign-request`, and forward the device's signature. The dApp expects these JSON-RPC
result shapes:

| Method | Result shape |
|---|---|
| `eth_sendTransaction` / `eth_signTransaction` | bare hex string |
| `personal_sign` / `eth_sign` / `eth_signTypedData*` | bare hex string |
| `solana_signTransaction` / `solana_signAndSendTransaction` | `{ signature: <base58> }` |
| `solana_signMessage` | `{ signature: <base58> }` |
| bip122 `signPsbt` | `{ psbt: <base64> }` |
| bip122 `signMessage` | `{ address, signature: <base64 BIP-137> }` |
| bip122 `sendTransfer` | `{ txid }` |
| `tron_signTransaction` / `tron_sendTransaction` | the tx object echoed with `signature: [<hex>]` |
| `tron_signMessage` | `{ signature: 0x<hex> }` |

When forwarding, set `dataType` from the method (e.g. `personal_sign` → `3`,
`eth_signTypedData*` → `2`, otherwise transaction). The verbatim-forward model applies to
EVM, Solana and Bitcoin; **Tron uses a different envelope but the same principle** — the
`raw_data_hex` bytes from the dApp request go **verbatim** into the `rawData` field of the
structured `keystone-sign-request` from [§4.4](#44-tron) (the semantic fields stay empty —
the dApp tx is opaque to the wallet); for `tron_signMessage` the UTF-8 message bytes travel
in the same `rawData` — the Tron path has no separate message type. Always
revalidate the recipient and calldata client-side before display — see [§9](#9-security--gotchas).

---

## 7. Reference tables

### 7.1 UR types

| UR type | Purpose | Response | Keystone tag |
|---|---|---|---|
| `crypto-multi-accounts` | account/key export (linking) | — | `1103` |
| `crypto-hdkey` | single account key export | — | `303` |
| `crypto-keypath` | derivation path (nested) | — | `304` |
| `eth-sign-request` | EVM tx / message | `eth-signature` (`402`) | `401` |
| `crypto-psbt` | BTC tx (PSBT) | `crypto-psbt` (`310`) | `310` |
| `crypto-psbt-extend` | LTC / DOGE / DASH tx — map `{1: PSBT, 2: coin id}`, LTC `2`, DOGE `3`, DASH `5` | `crypto-psbt-extend` (plain `crypto-psbt` is also answered) | device extension — **no** BCR/Keystone registry tag |
| `btc-sign-request` | BTC message | `btc-signature` (`8102`) | `8101` |
| `sol-sign-request` | Solana tx / message | `sol-signature` (`1102`) | `1101` |
| `keystone-sign-request` | Tron tx (any contract via `rawData`) / message; **Bitcoin Cash rides the same envelope** (coin code `"BCH"`, a `BchTx` protobuf) | `keystone-sign-result` (`6102`) | `6101` |
| `ton-sign-request` | TON tx (BoC) / TON Connect proof | `ton-signature` (`7202`) | `7201` |
| `cardano-sign-request` | Cardano tx (returns a witness set) | `cardano-signature` (`2203`) | `2202` |
| `sui-sign-request` | Sui BCS intent message | `sui-signature` (`7102`) | `7101` |
| `sui-sign-hash-request` | Sui 32-byte digest, carried as a **hex string** | `sui-signature` (`7102`) | `7103` |
| `cosmos-sign-request` | Cosmos SignDoc | `cosmos-signature` (`4102`) | `4101` |
| `evm-sign-request` | Cosmos/Ethermint SignDoc (keccak-256 zones) | `evm-signature` (`4102`) | `4101` |
| `bytes` | XRP tx JSON — untyped `ur:bytes` **both** directions, no registry tag, no request id | `bytes` (signed XRPL binary) | — |
| `qr-hardware-call` | ask the device for specific derivations (pull-model linking) | `crypto-multi-accounts` (`1103`) | `1201` |

### 7.2 `dataType` / `signType`

| Chain | Field | Values |
|---|---|---|
| EVM | `dataType` (key 3) | `1` transaction, `2` EIP-712, `3` personal_sign/raw, `4` typed transaction |
| BTC | `dataType` (key 3) | `1` message |
| Solana | `signType` (key 7) | (omitted) tx, `2` off-chain message |
| Tron | — | no `dataType`; the tx is a gzip protobuf inside `keystone-sign-request`, the signed bytes live in the `rawData` field; a (UTF-8) message travels in the same `rawData` |
| BCH | — | no `dataType`; the `BchTx` protobuf sits at field `10` of `SignTransaction` (coin code `"BCH"`), where Tron's `TronTx` sits at field `8` |
| Cosmos | `dataType` (key 3) | `1` Amino JSON SignDoc, `2` Direct (protobuf) SignDoc, `3` Textual, `4` ADR-036 message. The Ethermint `evm-sign-request` **remaps on the wire** — Amino → `2`, Direct → `3`; nothing else is accepted on that shape |
| Cardano | — | no `dataType`; `signData` (key 2) is the **full** tx CBOR array `[body, witness_set, is_valid, aux_data]` — the device extracts the body and signs its BLAKE2b-256 hash |
| Sui | — | no `dataType`; the request **type** carries it: `sui-sign-request` = BCS intent message (bytes), `sui-sign-hash-request` = a 32-byte digest as a hex string |
| TON | `dataType` (key 3) | `1` transaction (BoC; the device signs the root cell's representation hash), `2` TON Connect proof (`sha256(0xFFFF ‖ "ton-connect" ‖ sha256(signData))`) |
| XRP | — | none; the request payload is the transaction JSON, the reply the canonical signed XRPL binary |

### 7.3 Derivation paths / SLIP-44

| Chain | Account path | SLIP-44 | Address path |
|---|---|---|---|
| Bitcoin | `m/84'/0'/0'` | `0` | `0/idx` receive, `1/idx` change |
| EVM | `m/44'/60'/0'` | `60` | `0/idx` |
| Tron | `m/44'/195'/0'` | `195` | `0/idx` |
| Solana | `m/44'/501'/idx'` | `501` | (account path *is* the signer) |
| Bitcoin Cash | `m/44'/145'/0'` | `145` | `0/idx` receive, `1/idx` change |
| Litecoin | `m/84'/2'/0'` | `2` | `0/idx` receive, `1/idx` change |
| Dogecoin | `m/44'/3'/0'` | `3` | `0/idx` receive, `1/idx` change |
| Dash | `m/44'/5'/0'` | `5` | `0/idx` receive, `1/idx` change |
| TON | `m/44'/607'/0'` | `607` | (account path *is* the signer; the wallet-contract version changes only the address) |
| Cardano | `m/1852'/1815'/0'` | `1815` | `0/idx` payment, `2/0` stake (CIP-1852) |
| Sui | `m/44'/784'/0'/0'/0'` | `784` | fully hardened (SLIP-10 Ed25519) |
| Cosmos | `m/44'/118'/0'` | `118` | `0/idx`; Ethermint zones (INJ, EVMOS, DYM) use `m/44'/60'` |
| XRP | `m/44'/144'/0'` | `144` | `0/0` — the device always signs with `m/44'/144'/0'/0/0` |

---

## 8. Recommended libraries

| Concern | TypeScript / JS | Kotlin / Android | Swift / iOS | Dart / Flutter |
|---|---|---|---|---|
| UR codec | [`@ngraveio/bc-ur`](https://www.npmjs.com/package/@ngraveio/bc-ur) | [hummingbird](https://github.com/sparrowwallet/hummingbird) | [URKit](https://github.com/BlockchainCommons/URKit) | [`ur`](https://pub.dev/packages?q=uniform+resources) / vendored |
| Keystone registries | [`@keystonehq/bc-ur-registry-*`](https://www.npmjs.com/org/keystonehq) | [keystone-sdk (Android)](https://github.com/KeystoneHQ/keystone-sdk-android) | [keystone-sdk-ios](https://github.com/KeystoneHQ/keystone-sdk-ios) | hand-rolled CBOR |
| CBOR | [`cbor`](https://www.npmjs.com/package/cbor) / [`cbor-x`](https://www.npmjs.com/package/cbor-x) | [jackson-dataformat-cbor](https://github.com/FasterXML/jackson-dataformats-binary) | [SwiftCBOR](https://github.com/valpackett/SwiftCBOR) | [`cbor`](https://pub.dev/packages/cbor) |
| BIP32 / addresses | [`@scure/bip32`](https://github.com/paulmillr/scure-bip32), [`bitcoinjs-lib`](https://github.com/bitcoinjs/bitcoinjs-lib) | [bitcoinj](https://github.com/bitcoinj/bitcoinj), [kethereum](https://github.com/komputing/KEthereum) | [WalletCore](https://github.com/trustwallet/wallet-core) | [`bip32`](https://pub.dev/packages/bip32), [`bitcoin_base`](https://pub.dev/packages/bitcoin_base) |
| EVM tx | [viem](https://viem.sh/) / [ethers](https://docs.ethers.org/) | [web3j](https://github.com/web3j/web3j) | [WalletCore](https://github.com/trustwallet/wallet-core) | [`web3dart`](https://pub.dev/packages/web3dart) |
| Solana | [`@solana/web3.js`](https://solana-labs.github.io/solana-web3.js/) | [sol4k](https://github.com/sol4k/sol4k) | [Solana.Swift](https://github.com/metaplex-foundation/Solana.Swift) | [`solana`](https://pub.dev/packages/solana) |
| Tron | [tronweb](https://tronweb.network/) | [trident / java-tron](https://github.com/tronprotocol) | [WalletCore](https://github.com/trustwallet/wallet-core) | [`on_chain`](https://pub.dev/packages/on_chain) |
| Animated QR | [`@keystonehq/animated-qr`](https://www.npmjs.com/package/@keystonehq/animated-qr) | any QR view + UREncoder | any QR view + UREncoder | [`qr_flutter`](https://pub.dev/packages/qr_flutter) + UREncoder |

---

## 9. Security & gotchas

- **The device is the security boundary.** The user reviews and approves every signature
  on the device's own screen. You do not verify signatures to authorize — but you
  **should** revalidate the recipient address and calldata client-side *before* showing
  them, so what the user sees in your UI matches what the device will sign.
- **Use PSBT v0** for Bitcoin (§4.2) — it carries the global `UNSIGNED_TX` the device's
  signer reads; older firmware can fail on v2.
- **EIP-1559 field order** (§4.1): a missing `nonce` shifts all later fields and the
  broadcast fails. Always include every field in order.
- **EVM `v`:** the device returns the final `v` — recovery parity (`0`/`1`) for
  EIP-1559/2930 and messages; already EIP-155-encoded (`parity + chainId·2 + 35`) for legacy.
  Map parity → `27`/`28` only if a dApp expects that for a message.
- **Tron live block:** the `latestBlock` (§4.4) must come from a live now-block query with
  the **full** 64-hex block id, or the device will reference the wrong block.
- **Bitcoin change & gap limit:** derive change on the `1/idx` branch, prefer unused
  indices for privacy, and honor a gap limit when scanning for funds.
- **Integer math:** never use integer division for token amounts/fees — scale by
  `10^decimals` with floating/decimal math, and keep big values as big integers.
- **Animated QR robustness:** deduplicate frames, drive progress from the decoder, and be
  resilient to dropped/duplicate frames (the fountain code tolerates loss).

---

## 10. Standards & links

- **Uniform Resources (UR):**
  [BCR-2020-005 UR](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-005-ur.md) ·
  [BCR-2020-006 Registry](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-006-urtypes.md) ·
  [BCR-2020-007 HDKey/Keypath](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-007-hdkey.md) ·
  [BCR-2020-012 Bytewords](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-012-bytewords.md) ·
  [bc-ur reference](https://github.com/BlockchainCommons/bc-ur)
- **Keystone SDK & registries:**
  [keystone-sdk-base](https://github.com/KeystoneHQ/keystone-sdk-base) ·
  [@keystonehq on npm](https://www.npmjs.com/org/keystonehq)
- **CBOR:** [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949.html) · [cbor.io](https://cbor.io/)
- **UUID:** [RFC 9562](https://www.rfc-editor.org/rfc/rfc9562.html)
- **Fountain codes:** [Fountain code](https://en.wikipedia.org/wiki/Fountain_code) ·
  [Luby transform](https://en.wikipedia.org/wiki/Luby_transform_code)
- **Ethereum:**
  [EIP-1559](https://eips.ethereum.org/EIPS/eip-1559) ·
  [EIP-155](https://eips.ethereum.org/EIPS/eip-155) ·
  [EIP-191](https://eips.ethereum.org/EIPS/eip-191) ·
  [EIP-712](https://eips.ethereum.org/EIPS/eip-712) ·
  [EIP-2718](https://eips.ethereum.org/EIPS/eip-2718) ·
  [EIP-2930](https://eips.ethereum.org/EIPS/eip-2930)
- **Bitcoin:**
  [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) ·
  [BIP-44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki) ·
  [BIP-49](https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki) ·
  [BIP-84](https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki) ·
  [BIP-86](https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki) ·
  [BIP-137](https://github.com/bitcoin/bips/blob/master/bip-0137.mediawiki) ·
  [BIP-174 (PSBT)](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki) ·
  [BIP-173/350 (bech32)](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki)
- **Derivation registry:** [SLIP-44](https://github.com/satoshilabs/slips/blob/master/slip-0044.md) ·
  [SLIP-132 (zpub)](https://github.com/satoshilabs/slips/blob/master/slip-0132.md)
- **Solana:** [@solana/web3.js](https://solana-labs.github.io/solana-web3.js/)
- **Tron:** [protocol/core protobuf](https://github.com/tronprotocol/protocol/tree/master/core) ·
  [TronWeb](https://tronweb.network/)
- **WalletConnect:** [docs.reown.com](https://docs.reown.com/)

---

*This document describes the ERA hardware wallet's air-gapped QR protocol. It is a
protocol specification for integrators; it intentionally does not cover the device's
internal firmware or any companion-app implementation details.*

