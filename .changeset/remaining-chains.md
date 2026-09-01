---
"@hwlt/era-connect": minor
---

Add Sui, Cosmos and XRP modules, and extend the Bitcoin module to
Litecoin/Dogecoin/Dash via `crypto-psbt-extend`. Sui signs the BLAKE2b
intent digest (plus the hash-request variant) with local `0x` address
derivation; Cosmos covers ~35 zones in one module including the
Ethermint family (keccak digests, `evm-sign-request` wire shape); XRP
implements the XRP Toolkit `ur:bytes` convention with a mandatory
signed-binary verifier (canonical STObject walker + SHA-512-half
signing hash); the Bitcoin-family coins reuse the entire PSBT flow and
its anti-replay binding.
