# Cosmos (~35 networks)

Wire types: `cosmos-sign-request` (4101) → `cosmos-signature` (4102); the
Ethermint family (Injective, Evmos, Dymension) rides `evm-sign-request` →
`evm-signature` under the SAME tag, distinguished by the UR type string.

One module covers every zone — the network is your SignDoc's `chain_id`,
not a code path:

| Family | Path | Digest |
|---|---|---|
| Vanilla zones (ATOM, OSMO, TIA, SEI, dYdX, …) | `m/44'/118'/0'/0/0` (a few natives also expose their own coin type) | sha256 |
| Ethermint (INJ, EVMOS, DYM) | `m/44'/60'/0'/0/0` | keccak256 |

## 0. Accounts: one key, a prefix per zone

`accounts.cosmos()` is the linked `m/44'/118'/0'` account, and it derives
everything a request needs — the signing path, the fingerprint, the child key
and the address:

```ts
const cosmos = accounts.cosmos();
if (!cosmos) throw new Error('the export carries no Cosmos account');

cosmos.accountPath;                        // "m/44'/118'/0'"
cosmos.xfp;                                // what the sign request must carry
cosmos.pathFor(0);                         // "m/44'/118'/0'/0/0"
cosmos.derivePublicKey(0);                 // 33-byte compressed secp256k1
cosmos.deriveAddress(0, { chain: 'cosmos' });   // 'cosmos1…'
cosmos.deriveAddress(0, { chain: 'osmosis' });  // 'osmo1…' — the SAME key
```

The bech32 prefix is a property of the zone, not of the key: one key produces
`cosmos1…`, `osmo1…` and `celestia1…` from the same
`ripemd160(sha256(compressed pubkey))` payload. There is therefore no correct
default, and `deriveAddress` needs the zone named rather than inventing one.

## The zone registry

`COSMOS_CHAINS` is every zone the device can export a key for, with its HRP and
SLIP-44 coin type. Twenty-four of them share coin type 118, so the export
carries ONE key for all of them — **enumerate the registry, never the export's
entries**, or the same address appears two dozen times.

```ts
import { COSMOS_CHAINS, cosmosChain } from '@hwlt/era-connect';

COSMOS_CHAINS.length;                  // 33
cosmosChain('osmosis');                // { id, hrp: 'osmo', slip44: 118 }
accounts.availableCosmosChains();      // only the zones THIS export can serve
```

Zones with their own coin type — Secret 529, Cronos 394, Kava 459, Terra and
Terra Classic 330, THORChain 931 — are resolved by naming them, which picks the
entry they are actually derived under:

```ts
const kava = accounts.cosmos('kava')!;  // "m/44'/459'/0'"
kava.deriveAddress(0);                  // 'kava1…' — a bound view needs no options
```

`{ prefix }` remains for a zone the registry does not carry. It always means
the classic `hash160` recipe.

## Ethermint zones

Injective, Evmos and Dymension are EVM keys wearing a Cosmos coat: their
account is `m/44'/60'` and the bech32 payload is the **Ethereum** address, not
the `sha256+ripemd160` hash every other zone uses. Naming the zone picks both
the right entry and the right hashing:

```ts
accounts.cosmos('injective')!.deriveAddress(0);  // 'inj1…'
```

`ethermintAddressFromPublicKey` is exported for callers holding a key of their
own. Encoding an Ethermint zone with `cosmosAddressFromPublicKey` produces a
well-formed `inj1…` for a different account entirely.
ts
// 1 · request — Amino or Direct SignDoc bytes from your Cosmos tooling
const request = era.cosmos.generateSignRequest({
  signData: aminoJsonBytes,            // canonical JSON (UTF-8) or protobuf SignDoc
  dataType: CosmosChain.DataType.amino,
  path: cosmos.pathFor(0),             // "m/44'/118'/0'/0/0"
  xfp: cosmos.xfp,
  address: cosmos.deriveAddress(0, { chain: 'cosmos' }),
});
// Ethermint: const evm = accounts.evm()!;
//   era.cosmos.generateEthermintSignRequest({ ..., path: evm.pathFor(0), xfp: evm.xfp, address: evm.deriveAddress(0) })

// 2 · reply
const scanner = request.scanner();
const sig = scanner.parse();           // { signature (64B compact), publicKey (33B) }

// 3 · verify + broadcast — the VANILLA path
import { verifyCosmosSignature } from '@hwlt/era-connect/verify';
const check = verifyCosmosSignature({
  signData: aminoJsonBytes,
  digest: 'sha256',
  signature: sig.signature,
  publicKey: sig.publicKey!,                      // `cosmos-signature` carries it
  expectedPublicKey: cosmos.derivePublicKey(0),   // the binding — pass it
});
if (!check.ok) throw new Error(check.reason);
```

**Ethermint verifies differently — do not reach it by swapping `digest` in the
block above.** That reply is an `evm-signature`, which carries no public key at
all: `sig.publicKey` is `undefined`, and `verifyCosmosSignature` reads
`publicKey.length` before any guard, so `sig.publicKey!` throws a `TypeError`
instead of returning a verdict. Supply the key yourself.

```ts
// 3 · verify — the ETHERMINT path (Injective, Evmos, Dymension)
// The EVM view exposes the address rather than the key, so derive the
// `0/index` child from `accounts.evm()!.xpub()` with YOUR BIP-32 library.
const accountKey = bip32                     // YOUR BIP-32 library
  .fromExtendedKey(accounts.evm()!.xpub())
  .derive(0).derive(0).publicKey;            // 33-byte compressed
const check = verifyCosmosSignature({
  signData: signDocBytes,
  digest: 'keccak256',
  signature: sig.signature,
  publicKey: accountKey,   // your own key IS the binding here — see below
});
if (!check.ok) throw new Error(check.reason);
```

`expectedPublicKey` is what binds a reply to your account, and the two paths
need it differently. On a vanilla zone the reply brings its own key, and
without `expectedPublicKey` it would verify against itself — which any key can
do — so pass it. On Ethermint there is no reply key to compare: the signature
is checked against the key YOU derived, so verifying at all is the binding, and
`expectedPublicKey` would only compare that key with itself.

Assemble the `TxRaw`/`StdTx` with your Cosmos SDK tooling from the compact
signature + public key and broadcast as usual. The SDK performs no network I/O.
