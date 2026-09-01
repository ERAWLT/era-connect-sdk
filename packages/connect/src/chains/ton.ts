import { cborEncode } from '../cbor/encode';
import type { CborValue } from '../cbor/model';
import { cbBytes, cbMap, cbTag, cbText, cbUint, mapGet, stripTags } from '../cbor/model';
import { equalBytes, utf8Encode } from '../core/bytes';
import { EraSdkError } from '../core/errors';
import { normalizeRequestId, uuidStringify } from '../core/rand';
import { keypath304, normalizeXfp, parsePath } from '../registry/keypath';
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

/** `ton-sign-request` dataType (CBOR key 3). */
export const TonDataType = {
  /** `signData` is a Bag-of-Cells; the device signs the ROOT CELL's representation hash. */
  transaction: 1,
  /**
   * TON Connect proof: the device signs
   * `sha256(0xFFFF || "ton-connect" || sha256(signData))`.
   */
  tonProof: 2,
} as const;
export type TonDataType = (typeof TonDataType)[keyof typeof TonDataType];

export interface TonSignRequestProps {
  readonly requestId?: Uint8Array | string;
  /** BoC bytes (transaction) or the raw proof payload (tonProof). */
  readonly signData: Uint8Array;
  /** Defaults to `transaction`. */
  readonly dataType?: TonDataType;
  /** The account path, e.g. `m/44'/607'/0'` (V4R2 and V5R1 share it — the wallet-contract version affects only the address). */
  readonly path: string;
  readonly xfp: string | number;
  /** User-friendly bounceable address TEXT (`UQ…`/`EQ…`) — shown on the device. */
  readonly address?: string;
  readonly origin?: string;
}

export interface TonSignatureResult {
  readonly requestId: Uint8Array;
  /** 64-byte Ed25519 signature over the digest for the request's dataType. */
  readonly signature: Uint8Array;
}

const REPLY_TYPES = ['ton-signature'] as const;

export class TonChain {
  static readonly DataType = TonDataType;

  private readonly context: ChainContext;

  constructor(config?: EraConnectConfig) {
    this.context = resolveContext(config);
  }

  /** Build a `ton-sign-request` (7201). Reply: `ton-signature` (7202). */
  generateSignRequest(props: TonSignRequestProps): SignRequest<TonSignatureResult> {
    const requestId = resolveRequestId(this.context, props.requestId);
    const path = parsePath(props.path);
    const xfp = normalizeXfp(props.xfp);
    if (props.signData.length === 0) {
      throw new EraSdkError('invalid-props', 'signData must not be empty');
    }

    const entries: [number, CborValue][] = [
      // TON ecosystem quirk: the request id travels as the ASCII BYTES of the
      // hyphenated UUID string, wrapped in tag 37 (that is what Tonkeeper-
      // style integrations emit and what the device echoes back verbatim).
      [1, cbTag(37, cbBytes(utf8Encode(uuidStringify(requestId))))],
      [2, cbBytes(props.signData)],
      [3, cbUint(props.dataType ?? TonDataType.transaction)],
      [4, keypath304(path, xfp)],
    ];
    if (props.address !== undefined) entries.push([5, cbText(props.address)]);
    entries.push([6, cbText(props.origin ?? this.context.origin)]);

    const ur = new UrValue('ton-sign-request', cborEncode(cbMap(entries)));
    return makeSignRequest({
      ur,
      requestId,
      replyTypes: REPLY_TYPES,
      context: this.context,
      parse: (reply) => parseTonSignature(reply, requestId),
    });
  }

  /** Parse a `ton-signature` standalone. Prefer `SignRequest.scanner().parse()`. */
  parseSignature(input: Ur | string, expect?: ExpectedReply): TonSignatureResult {
    return parseTonSignature(
      toUr(input),
      expect?.requestId === undefined ? undefined : normalizeRequestId(expect.requestId),
    );
  }
}

function parseTonSignature(ur: Ur, expectedRequestId: Uint8Array | undefined): TonSignatureResult {
  requireUrType(ur, [...REPLY_TYPES], 'ton-signature');
  const map = requireReplyMap(ur, 'ton-signature');

  // The device echoes the request id BYTES verbatim (tag-37 wrapped). On this
  // chain those bytes are normally the ASCII of the UUID string; a bare
  // 16-byte binary echo is accepted too for forward compatibility.
  const echoedValue = mapGet(map, 1);
  const echoed = echoedValue === undefined ? undefined : stripTags(echoedValue);
  if (echoed?.kind !== 'bytes') {
    throw new EraSdkError('malformed-reply', 'ton-signature does not echo the request id (key 1)');
  }
  const requestId = normalizeEchoedId(echoed.value);
  if (expectedRequestId !== undefined) {
    if (requestId === null || !equalBytes(requestId, expectedRequestId)) {
      throw new EraSdkError(
        'request-id-mismatch',
        'ton-signature echoes a different request id — it answers another sign request, not this one',
      );
    }
  }

  const sigValue = mapGet(map, 2);
  const sig = sigValue === undefined ? undefined : stripTags(sigValue);
  if (sig?.kind !== 'bytes') {
    throw new EraSdkError('malformed-reply', 'ton-signature is missing the signature (key 2)');
  }
  if (sig.value.length !== 64) {
    throw new EraSdkError(
      'malformed-reply',
      `ton-signature signature is ${sig.value.length} bytes, expected 64`,
    );
  }
  return { requestId: requestId ?? new Uint8Array(16), signature: sig.value };
}

/** ASCII-UUID-string bytes (36) or raw binary (16) → 16-byte id; null if neither. */
function normalizeEchoedId(echoed: Uint8Array): Uint8Array | null {
  if (echoed.length === 16) return echoed;
  if (echoed.length === 36) {
    let text = '';
    for (const b of echoed) {
      if (b > 0x7f) return null;
      text += String.fromCharCode(b);
    }
    try {
      return normalizeRequestId(text);
    } catch {
      return null;
    }
  }
  return null;
}
