import { cborEncode } from '../cbor/encode';
import { asBytes, cbBytes, cbMap, cbText, mapGet } from '../cbor/model';
import { EraSdkError } from '../core/errors';
import { normalizeRequestId, uuidStringify } from '../core/rand';
import { normalizeXfp, parsePath, xfpToHex } from '../registry/keypath';
import { gunzipCapped, gzipCompress } from '../tron-proto/gzip';
import type { SignedTronTx, TronLatestBlock } from '../tron-proto/messages';
import {
  decodeSignResultProto,
  encodeSignRequestProto,
  splitSignedTronTx,
} from '../tron-proto/messages';
import type { Ur } from '../ur/ur';
import { Ur as UrValue } from '../ur/ur';
import type { ChainContext, EraConnectConfig, ExpectedReply, SignRequest } from './shared';
import {
  makeSignRequest,
  requireReplyMap,
  requireUrType,
  resolveContext,
  resolveRequestId,
  toUr,
} from './shared';

export type { TronLatestBlock } from '../tron-proto/messages';

export interface TronSignRequestProps {
  readonly requestId?: Uint8Array | string;
  /**
   * Serialized `Transaction.raw_data` — THE signing source of truth. The
   * device signs `sha256(rawData) = txID` and returns the transaction with
   * `raw_data` unmodified.
   */
  readonly rawData: Uint8Array;
  /** Full signing path, e.g. `m/44'/195'/0'/0/0`. */
  readonly path: string;
  readonly xfp: string | number;
  /**
   * Reference block context. Source it from a LIVE now-block query and pass
   * the FULL 64-hex block id.
   */
  readonly latestBlock: TronLatestBlock;
  /** On-device display only; safe to omit for opaque dApp transactions. */
  readonly display?: {
    readonly token?: string;
    readonly contractAddress?: string;
    readonly from?: string;
    readonly to?: string;
    readonly value?: string;
    readonly memo?: string;
    readonly fee?: number;
    readonly decimals?: number;
  };
  readonly timestamp?: number;
  readonly origin?: string;
}

export interface TronSignatureResult {
  readonly requestId: Uint8Array;
  /** `sha256(raw_data)` hex, as computed by the device. */
  readonly txId: string;
  /** Hex of the fully assembled signed transaction — broadcast as-is. */
  readonly rawTx: string;
  /** The signed frame split into `raw_data` + signatures (65-byte r||s||recovery each). */
  readonly signedTx: SignedTronTx;
}

/**
 * Ceilings on the gzip blob a `keystone-sign-result` may carry. Tron is the
 * only chain whose reply is compressed, so it is the only one where a few
 * hundred scanned bytes can ask for an arbitrary allocation. Generous
 * multiples of the largest real device reply.
 */
const MAX_COMPRESSED_BYTES = 8 * 1024;
const MAX_INFLATED_BYTES = 64 * 1024;

const REPLY_TYPES = ['keystone-sign-result'] as const;

/**
 * Tron signing rides the structured `keystone-sign-request` (6101) envelope —
 * a gzip-compressed protobuf inside CBOR `{1: gzip(protobuf), 2: origin}`.
 * The registry's generic `tron-sign-request` (5101) is NOT accepted by the
 * device and gets no response; do not emit it.
 */
export class TronChain {
  private readonly context: ChainContext;

  constructor(config?: EraConnectConfig) {
    this.context = resolveContext(config);
  }

  /** Build a `keystone-sign-request` (6101). Reply: `keystone-sign-result` (6102). */
  generateSignRequest(props: TronSignRequestProps): SignRequest<TronSignatureResult> {
    const requestId = resolveRequestId(this.context, props.requestId);
    parsePath(props.path); // validate shape; the wire carries the string form
    const xfp = normalizeXfp(props.xfp);
    if (props.rawData.length === 0) {
      throw new EraSdkError('invalid-props', 'rawData must not be empty');
    }
    if (!/^[0-9a-fA-F]{64}$/.test(props.latestBlock.hash)) {
      throw new EraSdkError(
        'invalid-props',
        'latestBlock.hash must be the FULL 64-hex block id (the device slices ref_block_hash from it)',
      );
    }

    const proto = encodeSignRequestProto({
      // Zero-padded to eight characters: the firmware parses this string with
      // a hex reader that yields 0 for anything shorter than 4 bytes, and a
      // zero fingerprint fails validation — a wallet whose fingerprint starts
      // with a zero byte (1 in 256) could not sign at all without the pad.
      xfpHex: xfpToHex(xfp),
      signId: uuidStringify(requestId),
      hdPath: props.path,
      timestamp: props.timestamp ?? 0,
      decimals: props.display?.decimals ?? 6,
      token: props.display?.token ?? '',
      contractAddress: props.display?.contractAddress,
      from: props.display?.from,
      to: props.display?.to,
      memo: props.display?.memo,
      value: props.display?.value,
      fee: props.display?.fee,
      latestBlock: props.latestBlock,
      rawData: props.rawData,
    });

    const ur = new UrValue(
      'keystone-sign-request',
      cborEncode(
        cbMap([
          [1, cbBytes(gzipCompress(proto))],
          [2, cbText(props.origin ?? this.context.origin)],
        ]),
      ),
    );
    return makeSignRequest({
      ur,
      requestId,
      replyTypes: REPLY_TYPES,
      context: this.context,
      parse: (reply) => parseTronSignature(reply, requestId),
    });
  }

  /**
   * Parse a `keystone-sign-result` standalone. Tron carries the request id
   * INSIDE the protobuf (`signId`); passing `expect.requestId` is what makes
   * the echo check possible here — prefer `SignRequest.scanner().parse()`.
   */
  parseSignature(input: Ur | string, expect?: ExpectedReply): TronSignatureResult {
    return parseTronSignature(
      toUr(input),
      expect?.requestId === undefined ? undefined : normalizeRequestId(expect.requestId),
    );
  }
}

function parseTronSignature(
  ur: Ur,
  expectedRequestId: Uint8Array | undefined,
): TronSignatureResult {
  requireUrType(ur, [...REPLY_TYPES], 'keystone-sign-result');
  const map = requireReplyMap(ur, 'keystone-sign-result');
  const compressed = asBytes(mapGet(map, 1));
  if (!compressed) {
    throw new EraSdkError('malformed-reply', 'keystone-sign-result is missing the payload (key 1)');
  }
  if (compressed.length > MAX_COMPRESSED_BYTES) {
    throw new EraSdkError(
      'limit-exceeded',
      `keystone-sign-result payload is ${compressed.length} bytes, over the ${MAX_COMPRESSED_BYTES} byte ceiling`,
    );
  }
  const result = decodeSignResultProto(gunzipCapped(compressed, MAX_INFLATED_BYTES));

  // The signId echo is the ONLY anti-replay binding on this chain — the
  // device's own bytes are broadcast verbatim, so a stale reply that skipped
  // this check would finalize a payment the user did not approve now.
  if (expectedRequestId !== undefined) {
    const expected = uuidStringify(expectedRequestId).toLowerCase();
    if (result.signId.toLowerCase() !== expected) {
      throw new EraSdkError(
        'request-id-mismatch',
        result.signId === ''
          ? 'keystone-sign-result does not echo the request id (signId)'
          : 'keystone-sign-result echoes a different request id — it answers another sign request, not this one',
      );
    }
  }
  if (result.rawTx === '') {
    throw new EraSdkError('malformed-reply', 'keystone-sign-result has no signed transaction');
  }
  const signedTx = splitSignedTronTx(result.rawTx);
  const requestId = expectedRequestId ?? signIdToBytes(result.signId);
  return { requestId, txId: result.txId, rawTx: result.rawTx, signedTx };
}

function signIdToBytes(signId: string): Uint8Array {
  try {
    return normalizeRequestId(signId);
  } catch {
    return new Uint8Array(16);
  }
}
