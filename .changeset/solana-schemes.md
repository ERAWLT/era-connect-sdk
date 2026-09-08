---
'@hwlt/era-connect': minor
---

`solana()` entries now say which derivation scheme they belong to.

The device ships all three Solana derivations, and the firmware tells them
apart by PATH DEPTH alone — all three carry the same `Derivation::Solana`.
`index` reads the third path level, so before this three different accounts all
reported index 0 with three different addresses, and two reported each of 1..4.

- `view.scheme` is `single` (`m/44'/501'`), `account` (`m/44'/501'/<n>'`) or
  `sub-account` (`m/44'/501'/<n>'/0'`).
- `solana({ scheme })` filters, which is what a wallet showing one account list
  actually wants.
- `index` is documented as unique only WITHIN a scheme.

Additive: an unfiltered `solana()` still returns every key the export shipped.
