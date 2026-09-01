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

```ts
// 1 · request — Amino or Direct SignDoc bytes from your Cosmos tooling
const request = era.cosmos.generateSignRequest({
  signData: aminoJsonBytes,            // canonical JSON (UTF-8) or protobuf SignDoc
  dataType: CosmosChain.DataType.amino,
  path: "m/44'/118'/0'/0/0",
  xfp,
  address: 'cosmos1…',
});
// Ethermint: era.cosmos.generateEthermintSignRequest({ ..., path: "m/44'/60'/0'/0/0", address: '0x…' })

// 2 · reply
const scanner = request.scanner();
const sig = scanner.parse();           // { signature (64B compact), publicKey (33B) }

// 3 · verify + broadcast
import { verifyCosmosSignature } from '@hwlt/era-connect/verify';
const check = verifyCosmosSignature({
  signData: aminoJsonBytes,
  digest: 'sha256',                    // 'keccak256' for Ethermint
  signature: sig.signature,
  publicKey: sig.publicKey!,
  expectedPublicKey,                   // derive from your linked xpub for real binding
});
```

Assemble the `TxRaw`/`StdTx` with your Cosmos SDK tooling from the compact
signature + public key and broadcast as usual. Bech32 address derivation per
zone prefix stays with your tooling.
