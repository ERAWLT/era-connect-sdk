---
'@hwlt/era-connect': minor
---

`accounts.btc({ purpose: 86 }).deriveAddress()` now returns a taproot address
instead of throwing.

**This is a behaviour change, and the behaviour it replaces was actively
harmful.** The SDK used to refuse purpose 86 and tell the caller to derive it
"from `xpub()` with your Bitcoin library". A consumer did exactly that, omitted
the BIP-341 tweak, and shipped a Receive screen offering a `bc1p…` built from
the untweaked internal key — a valid address that no BIP-86 signer, the ERA
device included, can key-path spend.

The witness program is the tweaked output key, never the BIP-32 child key:

```
P = lift_x(x(child))            // BIP-340 lift: always the even-Y point
t = int(taggedHash("TapTweak", x(P)))
Q = P + t*G
program = x(Q)                  // bech32m, witness version 1
```

`btcTaprootAddressFromPublicKey(publicKey33, hrp)` is exported for callers who
hold a key rather than an account view. No new dependency: `@noble/curves`
already exposes `lift_x` and the tagged hash, and `@scure/base` already exports
`bech32m`.

If you were catching `invalid-props` from `deriveAddress()` on a purpose-86
view as a supported control-flow path, that catch is now dead code.
