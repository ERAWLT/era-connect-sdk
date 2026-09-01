# EVM (Ethereum and every EVM chain)

One module signs for all EVM networks — the chain is a `chainId`, not a code
path. Wire types: `eth-sign-request` (tag 401) → `eth-signature` (402).

## 1. Generate the sign request

```ts
import { EvmChain } from '@era-wallet/connect/evm';

const request = era.evm.generateSignRequest(props);
```

| Prop | Type | Required | Notes |
|---|---|---|---|
| `signData` | `Uint8Array` | ✅ | The EXACT bytes to sign (below) |
| `dataType` | `EvmChain.DataType.*` | ✅ | `transaction` (1), `typedData` (2), `personalMessage` (3), `typedTransaction` (4) |
| `path` | `string` | ✅ | Full signing path, e.g. `m/44'/60'/0'/0/0` |
| `xfp` | `string \| number` | ✅ | Per-account fingerprint from linking |
| `chainId` | `number` | tx only | Must fit 32 bits — larger ids are refused (`invalid-props`) rather than silently truncated by the device into a signature for a different chain |
| `address` | `Uint8Array \| 0x-hex` | recommended | 20-byte signer; enables verification |
| `requestId` | `Uint8Array \| string` | – | 16 bytes / UUID; minted if omitted |
| `origin` | `string` | – | Overrides the SDK-level label |

**`signData` per dataType:**

- `transaction` / `typedTransaction` — the RLP payload *as signed*:
  - EIP-1559: `0x02 ‖ RLP([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList])`
  - legacy (EIP-155): `RLP([nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0])`
  - The device detects the tx kind from the leading byte — the two dataType
    values are equivalent; use `transaction`.
- `personalMessage` — the RAW message bytes. The device applies the EIP-191
  prefix itself; do not pre-prefix.
- `typedData` — the EIP-712 JSON document as UTF-8 bytes. The device parses
  and hashes the structure itself.

Payloads over 32 KiB still sign, but the device falls back to blind signing
(no decoded display); the request carries `warnings: ['blind-sign-threshold']`.

```ts
// viem example — EIP-1559
import { serializeTransaction, parseGwei } from 'viem';
const unsigned = { chainId: 1, nonce, maxPriorityFeePerGas, maxFeePerGas,
                   gas, to, value, data, type: 'eip1559' as const };
const signData = hexToBytes(serializeTransaction(unsigned)); // 0x02‖RLP(...)
```

## 2. Parse the signature

```ts
const scanner = request.scanner();   // create ONCE, feed it the camera frames
// ... scanner.receivePart(frame) until { kind: 'complete' } ...
const sig = scanner.parse();         // or era.evm.parseSignature(ur, { requestId })
```

| Field | Type | Notes |
|---|---|---|
| `signature` | `Uint8Array` | Raw `r‖s‖v`, ≥ 65 bytes |
| `r`, `s` | `Uint8Array` | 32 bytes each |
| `v` | `bigint` | **As the device sent it** — parity (0/1) for typed txs, 27/28 for messages, and for legacy txs ALREADY `parity + chainId·2 + 35` (more than one byte past chain id 110). Never re-apply the EIP-155 formula. |
| `recoveryId` | `0 \| 1` | `v` folded down, whichever form it arrived in |

## 3. Assemble & broadcast

```ts
import { serializeTransaction } from 'viem';
import { verifyEvmSignature } from '@era-wallet/connect/verify';

const check = verifyEvmSignature({ signData, dataType, signature: sig.signature, address });
if (!check.ok) throw new Error(check.reason);

const raw = serializeTransaction(unsigned, {
  r: `0x${bytesToHex(sig.r)}`,
  s: `0x${bytesToHex(sig.s)}`,
  yParity: sig.recoveryId,
});
await client.sendRawTransaction({ serializedTransaction: raw });
```

For messages returned to a dApp expecting `27/28`: `v = recoveryId + 27`.
