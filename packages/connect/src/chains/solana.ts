import { base58 } from '@scure/base';
import { cborEncode } from '../cbor/encode';
import type { CborValue } from '../cbor/model';
import { cbBytes, cbMap, cbText, cbUint, mapGet, stripTags } from '../cbor/model';
import { hexToBytes } from '../core/bytes';
import { EraSdkError } from '../core/errors';
import { normalizeRequestId } from '../core/rand';
import { keypath304, normalizeXfp, parsePath } from '../registry/keypath';
import type { Ur } from '../ur/ur';
import { Ur as UrValue } from '../ur/ur';
import type { ChainContext, EraConnectConfig, ExpectedReply, SignRequest } from './shared';
import {
  makeSignRequest,
  resolveContext,
  requireReplyMap,
  requireRequestIdEcho,
  requireUrType,
  resolveRequestId,
  toUr,
} from './shared';

/** `sol-sign-request` signType (CBOR key 7). */
export const SolSignType = {
  /** Key 7 is OMITTED on the wire for a transaction (the device's default). */
  transaction: 1,
  /** Off-chain message: key 7 = 2. The device signs the bytes VERBATIM (no prefix). */
  message: 2,
} as const;
export type SolSignType = (typeof SolSignType)[keyof typeof SolSignType];

export interface SolSignRequestProps {
  readonly requestId?: Uint8Array | string;
  /** Compiled transaction MESSAGE bytes (legacy or versioned), or raw message bytes. */
  readonly signData: Uint8Array;
  /** Defaults to `transaction`. */
  readonly signType?: SolSignType;
  /**
   * The 3-level hardened account path `m/44'/501'/idx'` — the exported
   * account IS the signer (Ed25519 has no public child derivation).
   */
  readonly path: string;
  readonly xfp: string | number;
  /** 32-byte Ed25519 public key, or its base58 address form. One of the two is required. */
  readonly publicKey?: Uint8Array;
  readonly address?: string;
  readonly origin?: string;
}

export interface SolSignatureResult {
  readonly requestId: Uint8Array;
  /** 64-byte Ed25519 signature. */
  readonly signature: Uint8Array;
}

const REPLY_TYPES = ['sol-signature'] as const;

export class SolanaChain {
  static readonly SignType = SolSignType;

  private readonly context: ChainContext;

  constructor(config?: EraConnectConfig) {
    this.context = resolveContext(config);
  }

  /** Build a `sol-sign-request` (1101). Reply: `sol-signature` (1102). */
  generateSignRequest(props: SolSignRequestProps): SignRequest<SolSignatureResult> {
    const requestId = resolveRequestId(this.context, props.requestId);
    const path = parsePath(props.path);
    if (path.length !== 3 || !path.every((l) => l.hardened)) {
      throw new EraSdkError(
        'invalid-props',
        `Solana signing path must be the 3-level hardened account path (m/44'/501'/idx'), got ${props.path}`,
      );
    }
    const xfp = normalizeXfp(props.xfp);
    const publicKey = resolvePublicKey(props);

    const entries: [number, CborValue][] = [
      [1, cbBytes(requestId)],
      [2, cbBytes(props.signData)],
      [3, keypath304(path, xfp)],
      [4, cbBytes(publicKey)],
      [5, cbText(props.origin ?? this.context.origin)],
      [6, cbUint(1)], // version
    ];
    if ((props.signType ?? SolSignType.transaction) === SolSignType.message) {
      entries.push([7, cbUint(SolSignType.message)]);
    }
    const ur = new UrValue('sol-sign-request', cborEncode(cbMap(entries)));

    return makeSignRequest({
      ur,
      requestId,
      replyTypes: REPLY_TYPES,
      context: this.context,
      parse: (reply) => parseSolSignature(reply, requestId),
    });
  }

  /** Parse a `sol-signature` standalone. Prefer `SignRequest.scanner().parse()`. */
  parseSignature(input: Ur | string, expect?: ExpectedReply): SolSignatureResult {
    return parseSolSignature(
      toUr(input),
      expect?.requestId === undefined ? undefined : normalizeRequestId(expect.requestId),
    );
  }
}

function resolvePublicKey(props: SolSignRequestProps): Uint8Array {
  if (props.publicKey !== undefined) {
    if (props.publicKey.length !== 32) {
      throw new EraSdkError('invalid-props', 'Solana public key must be 32 bytes');
    }
    return props.publicKey;
  }
  if (props.address !== undefined) {
    let decoded: Uint8Array;
    try {
      decoded = base58.decode(props.address);
    } catch {
      throw new EraSdkError('invalid-props', 'Solana address is not base58');
    }
    if (decoded.length !== 32) {
      throw new EraSdkError('invalid-props', 'Solana address does not decode to 32 bytes');
    }
    return decoded;
  }
  throw new EraSdkError('invalid-props', 'provide publicKey or address');
}

function parseSolSignature(ur: Ur, expectedRequestId: Uint8Array | undefined): SolSignatureResult {
  requireUrType(ur, [...REPLY_TYPES], 'sol-signature');
  const map = requireReplyMap(ur, 'sol-signature');
  const requestId = requireRequestIdEcho(map, 1, expectedRequestId, 'sol-signature');

  const raw = mapGet(map, 2);
  const value = raw === undefined ? undefined : stripTags(raw);
  // The firmware encodes the signature as CBOR bytes; a hex text string is
  // accepted too (older firmware sent that shape).
  let signature: Uint8Array;
  if (value?.kind === 'bytes') {
    signature = value.value;
  } else if (value?.kind === 'text') {
    try {
      signature = hexToBytes(value.value);
    } catch {
      throw new EraSdkError('malformed-reply', 'sol-signature signature is not hex');
    }
  } else {
    throw new EraSdkError('malformed-reply', 'sol-signature is missing the signature (key 2)');
  }
  if (signature.length !== 64) {
    throw new EraSdkError(
      'malformed-reply',
      `sol-signature signature is ${signature.length} bytes, expected 64`,
    );
  }
  return { requestId, signature };
}
