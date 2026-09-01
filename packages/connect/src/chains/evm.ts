import { cborEncode } from '../cbor/encode';
import type { CborValue } from '../cbor/model';
import { cbBytes, cbMap, cbText, cbUint, mapGet } from '../cbor/model';
import { bytesToBigint, hexToBytes } from '../core/bytes';
import { EraSdkError } from '../core/errors';
import { normalizeRequestId } from '../core/rand';
import { keypath304, normalizeXfp, parsePath } from '../registry/keypath';
import type { Ur } from '../ur/ur';
import { Ur as UrValue } from '../ur/ur';
import type { ChainContext, EraConnectConfig, ExpectedReply, SignRequest } from './shared';
import {
  makeSignRequest,
  requireReplyMap,
  requireRequestIdEcho,
  requireSignatureBytes,
  requireUrType,
  resolveContext,
  resolveRequestId,
  toUr,
} from './shared';

/** `eth-sign-request` dataType (CBOR key 3). */
export const EvmDataType = {
  /** RLP-encoded transaction (the device sniffs EIP-1559/2930/legacy from the leading byte). */
  transaction: 1,
  /** EIP-712 typed data JSON (UTF-8 bytes). */
  typedData: 2,
  /** personal_sign / raw message bytes (EIP-191 prefix applied by the device). */
  personalMessage: 3,
  /** Typed (EIP-2718) transaction bytes — treated identically to `transaction`. */
  typedTransaction: 4,
} as const;
export type EvmDataType = (typeof EvmDataType)[keyof typeof EvmDataType];

export interface EvmSignRequestProps {
  /** 16 bytes or a UUID string; minted if omitted. */
  readonly requestId?: Uint8Array | string;
  /** RLP tx bytes, typed-data JSON UTF-8, or raw message bytes. */
  readonly signData: Uint8Array;
  readonly dataType: EvmDataType;
  /** Full signing path, e.g. `m/44'/60'/0'/0/0`. */
  readonly path: string;
  /** The account's source fingerprint from the linked wallet (`EraAccounts.xfpFor(...)`). */
  readonly xfp: string | number;
  /**
   * Required for transactions (it derives the legal reply width). The device
   * reads it as an unsigned 32-bit value — larger chain ids are refused here,
   * because a silently truncated id would sign for a different chain.
   */
  readonly chainId?: number;
  /** 20-byte signer address; recommended (enables verification helpers). */
  readonly address?: Uint8Array | `0x${string}`;
  /** Overrides the SDK-level origin label for this request. */
  readonly origin?: string;
}

export interface EvmSignatureResult {
  readonly requestId: Uint8Array;
  /** Raw `r || s || v` exactly as the device sent it (may exceed 65 bytes for legacy EIP-155). */
  readonly signature: Uint8Array;
  readonly r: Uint8Array;
  readonly s: Uint8Array;
  /**
   * The recovery value AS SENT: parity (0/1) for typed transactions, 27/28
   * for messages, already-EIP-155-encoded (`parity + chainId*2 + 35`) for
   * legacy transactions. Do NOT re-apply the EIP-155 formula.
   */
  readonly v: bigint;
  /** `v` folded to a plain 0/1 recovery id, whichever of the three forms it arrived in. */
  readonly recoveryId: 0 | 1;
}

/** Over this size the device skips transaction decoding and falls back to blind signing. */
const BLIND_SIGN_THRESHOLD = 32 * 1024;

const REPLY_TYPES = ['eth-signature', 'evm-signature'] as const;

export class EvmChain {
  static readonly DataType = EvmDataType;

  private readonly context: ChainContext;

  constructor(config?: EraConnectConfig) {
    this.context = resolveContext(config);
  }

  /** Build an `eth-sign-request` (401). Reply: `eth-signature` (402). */
  generateSignRequest(props: EvmSignRequestProps): SignRequest<EvmSignatureResult> {
    const requestId = resolveRequestId(this.context, props.requestId);
    const path = parsePath(props.path);
    const xfp = normalizeXfp(props.xfp);
    const isTransaction =
      props.dataType === EvmDataType.transaction || props.dataType === EvmDataType.typedTransaction;

    if (isTransaction && props.chainId === undefined) {
      throw new EraSdkError('invalid-props', 'chainId is required for transaction sign requests');
    }
    if (props.chainId !== undefined) {
      if (!Number.isSafeInteger(props.chainId) || props.chainId < 0) {
        throw new EraSdkError('invalid-props', 'chainId must be a non-negative integer');
      }
      if (props.chainId > 0xffffffff) {
        throw new EraSdkError(
          'invalid-props',
          `chainId ${props.chainId} exceeds the device's unsigned 32-bit range; ` +
            'a truncated id would produce a signature for a different chain',
          { chainId: props.chainId },
        );
      }
    }

    const entries: [number, CborValue][] = [
      [1, cbBytes(requestId)],
      [2, cbBytes(props.signData)],
      [3, cbUint(props.dataType)],
    ];
    if (props.chainId !== undefined) entries.push([4, cbUint(props.chainId)]);
    entries.push([5, keypath304(path, xfp)]);
    if (props.address !== undefined) entries.push([6, cbBytes(normalizeAddress(props.address))]);
    entries.push([7, cbText(props.origin ?? this.context.origin)]);

    const ur = new UrValue('eth-sign-request', cborEncode(cbMap(entries)));
    const warnings: string[] = [];
    if (props.signData.length > BLIND_SIGN_THRESHOLD) warnings.push('blind-sign-threshold');

    const maxSigLength = 64 + maxVBytes(props.dataType, props.chainId);
    return makeSignRequest({
      ur,
      requestId,
      replyTypes: REPLY_TYPES,
      warnings,
      context: this.context,
      parse: (reply) => parseEvmSignature(reply, { requestId }, maxSigLength),
    });
  }

  /**
   * Parse an `eth-signature` standalone. Without `expect.requestId` the echo
   * is returned but not validated — prefer `SignRequest.scanner().parse()`.
   */
  parseSignature(input: Ur | string, expect?: ExpectedReply): EvmSignatureResult {
    const expected =
      expect?.requestId === undefined
        ? undefined
        : { requestId: normalizeRequestId(expect.requestId) };
    return parseEvmSignature(toUr(input), expected, 64 + 8);
  }
}

function normalizeAddress(address: Uint8Array | `0x${string}`): Uint8Array {
  const bytes = address instanceof Uint8Array ? address : hexToBytes(address);
  if (bytes.length !== 20) {
    throw new EraSdkError('invalid-props', 'EVM address must be 20 bytes');
  }
  return bytes;
}

/**
 * Width of the widest `v` the device can legitimately return.
 *
 * For a legacy EIP-155 transaction `v = parity + chainId*2 + 35` — 2 bytes
 * past chain id 110, 4 bytes for Aurora. Messages and typed data always
 * answer with one byte (27/28). A flat ceiling either refuses genuine replies
 * on large-id chains or accepts implausibly wide values; the exact bound
 * comes from the request.
 */
function maxVBytes(dataType: EvmDataType, chainId: number | undefined): number {
  if (dataType !== EvmDataType.transaction && dataType !== EvmDataType.typedTransaction) return 1;
  if (chainId === undefined) return 8;
  let widest = BigInt(chainId) * 2n + 36n;
  if (widest < 28n) widest = 28n;
  let bytes = 0;
  while (widest > 0n) {
    bytes += 1;
    widest >>= 8n;
  }
  return bytes;
}

function parseEvmSignature(
  ur: Ur,
  expect: { requestId: Uint8Array } | undefined,
  maxSigLength: number,
): EvmSignatureResult {
  requireUrType(ur, [...REPLY_TYPES], 'eth-signature');
  const map = requireReplyMap(ur, 'eth-signature');
  const requestId = requireRequestIdEcho(map, 1, expect?.requestId, 'eth-signature');
  const signature = requireSignatureBytes(mapGet(map, 2), 'eth-signature', 65, maxSigLength);

  const r = signature.slice(0, 32);
  const s = signature.slice(32, 64);
  const v = bytesToBigint(signature.slice(64));
  const recoveryId = foldRecoveryId(v);
  if (recoveryId !== 0 && recoveryId !== 1) {
    throw new EraSdkError(
      'malformed-reply',
      `eth-signature carries an implausible recovery value ${v}`,
    );
  }
  return { requestId, signature, r, s, v, recoveryId };
}

/** Fold parity / 27-28 / EIP-155 forms of `v` to a 0/1 recovery id. */
export function foldRecoveryId(v: bigint): number {
  if (v >= 35n) return Number((v - 35n) & 1n);
  if (v >= 27n) return Number(v - 27n);
  return Number(v);
}
