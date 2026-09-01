# Verification — "did the device sign exactly what I sent?"

`@hwlt/era-connect/verify` (its own subpath, so the curve arithmetic stays
out of bundles that skip it) answers the one question the transport cannot:
that the signature in hand covers **the bytes you are about to broadcast**,
made by **the key you expected**.

The camera is an untrusted channel — a QR is a QR, whoever printed it. The
scanner's type pinning and the request-id echo already refuse replays and
strays; these helpers close the cryptographic half. Run them between
`parse()` and broadcast. They return a result, never throw:

```ts
type VerifyResult =
  | { ok: true;  checked: true }                  // cryptographically verified
  | { ok: true;  checked: false; reason: string } // nothing verifiable client-side
  | { ok: false; reason: string };
```

| Helper | Proves | Notes |
|---|---|---|
| `verifyEvmSignature` | keccak digest recovery → your address | Handles multi-byte legacy `v`. Pass `reEncodedSignData` (the payload re-derived from the tx you will broadcast) to also prove nothing drifted between build and send |
| `verifySignedPsbt` | Returned PSBT = sent PSBT + signatures, nothing else | **Mandatory** — `crypto-psbt` has no request id, this comparison IS the anti-replay binding. Also refuses finalized script fields the device did not receive and partial signing |
| `verifyBtcMessageHeader` | BIP-137 header names your address kind | A wrong header looks like success locally and fails in every downstream verifier |
| `verifySolanaSignature` | Ed25519 verify against the signer key | Pass `broadcastMessageBytes` — on Solana "what was signed" and "what you send" drift legitimately (blockhash refresh) and must agree |
| `verifyTronSignature` | Every signature recovers to the owner; `raw_data` byte-equal, or (rebuild path) same operation + validity window | An operation it cannot compare field-by-field is refused |
| `verifyBchSignedTx` | Every outpoint/output/value equals the request; each input signed by the requested key with sighash 0x41, re-verified against a locally recomputed BIP-143 FORKID sighash | **Mandatory** — the reply is a complete broadcastable transaction; the `signId` echo alone does not prove its contents |

## The honest gap: EIP-712

For `dataType: typedData` the digest is the hash of the *structure*, computed
only on the device — there is nothing client-side to recover against.
`verifyEvmSignature` says so explicitly (`ok: true, checked: false`) instead
of pretending. The binding for typed data is the reply's UR type plus the
request-id echo — both enforced in `parse()` — and the path never broadcasts:
the signature returns to the dApp, which verifies the recovered address
itself.
