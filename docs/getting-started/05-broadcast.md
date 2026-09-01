# 5. Verify & broadcast

The reply parsed and the request id matched. One step remains before
broadcasting: prove the signature covers **exactly the bytes you sent** — and
then send the transaction with your own infrastructure (the SDK never
performs I/O).

```ts
import { verifyEvmSignature } from '@era-wallet/connect/verify';

const check = verifyEvmSignature({
  signData: rlpBytes,
  dataType: EvmChain.DataType.transaction,
  signature: signature.signature,
  address: evm.deriveAddress(0),
});
if (!check.ok) throw new Error(check.reason);
```

Why bother, when the device is trusted? Because the *camera* is not: the QR
path is an untrusted channel, and these helpers are what turn "a plausible
signature arrived" into "the key I expected signed the bytes I sent". For
Bitcoin PSBTs the verification is not even optional — `crypto-psbt` replies
carry no request id, so comparing the returned PSBT against the sent one IS
the anti-replay binding:

```ts
import { verifySignedPsbt } from '@era-wallet/connect/verify';
const check = verifySignedPsbt({ sentPsbt, signedPsbt: reply.psbt });
```

See [Verification](../advanced/verification.md) for what each helper proves
and the one honest gap (EIP-712 digests exist only on the device).

## Assemble & broadcast

Chain-specific: attach `r/s/v` and re-encode (EVM), finalize the PSBT
(Bitcoin), attach the 64-byte signature (Solana), or broadcast the returned
`rawTx` hex verbatim (Tron). Each [chain guide](../chains/evm.md) ends with a
copy-pasteable assembly snippet for the mainstream tooling.

---

That is the whole integration: **link → request → scan → verify → broadcast**.
The per-chain pages document every field; [device-specifics](../advanced/device-specifics.md)
lists the handful of places the device deviates from the generic Keystone
registry — all already encoded in this SDK, listed so you are never surprised.
