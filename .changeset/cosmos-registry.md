---
'@hwlt/era-connect': minor
---

The whole Cosmos family is addressable, Ethermint included.

`COSMOS_CHAINS` is the registry the firmware's `CosmosCoinInfo` table declares:
33 zones with their HRP and SLIP-44. Twenty-four of them share coin type 118,
so the export carries ONE key for all of them and only the HRP differs —
**enumerate the registry, never the export's entries**, or a caller sees two
dozen identical rows for the same address.

- `cosmos()` with no argument is unchanged: the shared 118 account.
- `cosmos('kava')` resolves the entry that zone is actually derived under —
  the six non-118 chains have their own coin types (Secret 529, Cronos 394,
  Kava 459, Terra and Terra Classic 330, THORChain 931).
- `availableCosmosChains()` lists only the zones a given export can serve.
- `deriveAddress(i, { chain })` picks the hashing as well as the HRP;
  `{ prefix }` stays the escape hatch for zones the registry does not carry and
  always means the classic recipe.

**Ethermint** (Injective, Evmos, Dymension) are EVM keys wearing a Cosmos coat:
their account is `m/44'/60'` and the bech32 payload is the ETHEREUM address,
not `sha256+ripemd160`. `cosmos('injective')` therefore resolves the EVM
account and encodes with `ethermintAddressFromPublicKey`, which is also
exported. Encoding one of these with the classic recipe yields a well-formed
`inj1…` for a different account entirely, so the two recipes are separate
functions rather than a flag.
