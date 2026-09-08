---
'@hwlt/era-connect': minor
---

TON addresses, instead of "use your TON library".

`TonAccountView.address` is the V4R2 wallet address (`UQ…`, non-bounceable —
the form a wallet shows for receiving), `.bounceableAddress` the `EQ…` form,
and `tonAddressFromPublicKey(key)` is exported.

A TON address is not a hash of the key: it is the hash of the wallet CONTRACT
the key would deploy. `StateInit{code, data}` is a cell with two refs, its
representation hash is the account id, and the friendly form is
`tag || workchain || account_id || crc16` in base64url. The code cell never
varies, so only its hash and depth are carried — the same two constants the
firmware uses, not a whole embedded BOC.

The test vector is the firmware's own device-verified regression case, and the
public key it uses was derived independently rather than by this package.

V5R1 is deliberately not implemented: the firmware declares it, but every
wallet-link profile clamps TON to derivation index 0, so no export carries it
and an implementation could not be exercised against real device output.
