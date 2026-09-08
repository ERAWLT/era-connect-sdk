---
'@hwlt/era-connect': minor
---

The two Ledger EVM schemes are visible.

The device exports three EVM derivations and `evm()` answers only the standard
one, so the other two were in the export and unreachable. They are not
interchangeable with it, or with each other:

- `evmLedgerLive()` — ten fully derived LEAVES at `m/44'/60'/<n>'/0/0`, one key
  per account with nothing to derive further. Asking such a view for index 1
  throws rather than deriving below a leaf.
- `evmLedgerLegacy()` — an account whose addresses sit ONE level below it,
  `m/44'/60'/0'/<index>`, not two. Deriving it like the standard account gives
  a different address.

Ledger Live leaves and the Ethermint keys share a path shape; the chain code is
what separates them, and only the former are returned here.

`derivePublicKeyChild` is exported for the single-step case.
