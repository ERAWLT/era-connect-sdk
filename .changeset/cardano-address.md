---
'@hwlt/era-connect': minor
---

Cardano addresses, instead of "use your Cardano library".

`CardanoAccountView.deriveAddress(i, { change })` returns the Shelley BASE
address, and `cardanoBaseAddress(paymentKey, stakeKey)` is exported for callers
holding keys of their own. The SDK already soft-derived the keys; only the
assembly was missing.

    header(1) || blake2b224(payment_vkey) || blake2b224(stake_vkey)

Header `0x01` — address type 0, network id 1 — bech32 (not bech32m) under the
HRP `addr`, exactly as the firmware's `CardanoAddress.cpp` builds it. A base
address commits to BOTH keys, which is why the function takes two: an address
built from the payment key alone is an *enterprise* address, a different thing
that cannot delegate its stake. The stake key is the one at `2/0`.
