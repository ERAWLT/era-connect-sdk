---
'@hwlt/era-connect': minor
---

Litecoin, Dogecoin and Dash are now named and addressable, and `evm()` no
longer answers with a leaf.

**Altcoins.** The SDK signed PSBTs for these three (`PsbtCoin.ltc`, `.doge`,
`.dash`) long before it could name an address for them: `classify` returned
`unknown` and there was no view, so a caller holding a perfectly good Litecoin
account had no way to ask where to receive. They are now classified at their
own mainnet coin types — 2', 3', 5' — and `wallet.litecoin()`,
`.dogecoin()`, `.dash()` return a `UtxoAccountView`.

The encoding is the machinery Bitcoin already uses under different version
bytes, taken from each coin's `CoinInfo` in the firmware: LTC 48/50 (`L…`,
`M…`, `ltc1q…`), DOGE 30/22 (`D…`), DASH 76/16 (`X…`).
`p2pkhAddressFromPublicKey` and `nestedSegwitAddressFromPublicKey` take the
version byte explicitly and are exported; the Bitcoin-specific helpers now
delegate to them and keep their signatures.

**`evm()` guard.** `classify` reads only the first two path levels, and three
different things start `m/44'/60'`: the account, the Ledger Live leaves
`m/44'/60'/<n>'/0/0`, and the Ethermint keys Injective / Evmos / Dymension are
exported under. `evm()` took the first entry that classified as evm, so it
could hand back a leaf — and a view over a leaf reports the leaf as its account
path and derives two levels below it, answering a real key at a nonsense path.
It now requires an account-shaped entry (depth 3).
