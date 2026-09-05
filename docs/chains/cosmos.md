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
cosmos.deriveAddress(0, { prefix: 'cosmos' }); // 'cosmos1…'
cosmos.deriveAddress(0, { prefix: 'osmo' });   // 'osmo1…' — the SAME key
```

The bech32 prefix is a property of the zone, not of the key: one key produces
`cosmos1…`, `osmo1…` and `celestia1…` from the same
`ripemd160(sha256(compressed pubkey))` payload. There is therefore no correct
default, and `deriveAddress` requires a `prefix` rather than inventing one.

Ethermint zones are the exception and are not this account: they sign with
`m/44'/60'` keys, so they come back from `accounts.evm()`.

`cosmos()` means `m/44'/118'` and nothing else. An account exported under
another coin type — Terra's 330, Kava's 459, Secret's 529 — is a family this
SDK does not classify: `cosmos()` returns `undefined` and the entry's `chain`
reads `'unknown'`. Take those out of `accounts.keys` by path, derive the
`0/index` child with your own BIP-32 library from the entry's `publicKey` +
`chainCode`, and hand the result to `cosmosAddressFromPublicKey`, which is
exported from the package root for exactly this:

```ts
import { cosmosAddressFromPublicKey } from '@hwlt/era-connect';

const entry = accounts.keys.find((k) => k.path === "m/44'/330'/0'")!;
const child = bip32                        // YOUR BIP-32 library
  .fromPublicKey(entry.publicKey!, entry.chainCode!)
  .derive(0).derive(0).publicKey;

const request = era.cosmos.generateSignRequest({
  signData, dataType: CosmosChain.DataType.direct,
  path: `${entry.path}/0/0`,
  xfp: accounts.xfpFor(entry.path),            // throws, never a silent zero
  address: cosmosAddressFromPublicKey(child, 'terra'),
});
```

```ts
// 1 · request — Amino or Direct SignDoc bytes from your Cosmos tooling
const request = era.cosmos.generateSignRequest({
  signData: aminoJsonBytes,            // canonical JSON (UTF-8) or protobuf SignDoc
  dataType: CosmosChain.DataType.amino,
  path: cosmos.pathFor(0),             // "m/44'/118'/0'/0/0"
  xfp: cosmos.xfp,
  address: cosmos.deriveAddress(0, { prefix: 'cosmos' }),
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
