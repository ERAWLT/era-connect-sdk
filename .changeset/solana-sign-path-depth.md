---
'@hwlt/era-connect': minor
---

`era.solana.generateSignRequest` accepts every derivation scheme the device
exports, not one of three.

The guard demanded exactly three hardened levels, so `m/44'/501'` — the "Single
Account Path", which is the address the hardware wallet's OWN Receive screen
shows by default — and `m/44'/501'/idx'/0'`, the "Sub-account Path" that Phantom
and Solflare use, could not be signed through this package at all. A wallet
offering the device's default address had no way to spend from it.

The firmware has always signed all three: it derives at the FULL path the
request carries, its path parser refuses only an empty path, and the only gate
is the request's source fingerprint matching the master or the parent — which
every exported entry satisfies. The guard was ours alone, and narrower than the
device.

The rule is now **fully hardened, 2 to 4 levels**, exactly the set of depths
`SolanaScheme` already distinguishes. Pass the entry's own `path` through; do
not rebuild it.

The coin type stays unchecked on purpose: the old guard never looked at it, and
policing it here would refuse paths that sign today, in a release whose only
claim is to accept more.
