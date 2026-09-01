import { cborEncode } from '../cbor/encode';
import type { CborValue } from '../cbor/model';
import { asBytes, cbArray, cbBytes, cbMap, cbTag, cbText, cbUint, mapGet } from '../cbor/model';
import { utf8Encode } from '../core/bytes';
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
  requireUrType,
  resolveContext,
  resolveRequestId,
  toUr,
} from './shared';

/** `cosmos-sign-request` dataType (CBOR key 3). */
export const CosmosDataType = {
  /** SIGN_MODE_LEGACY_AMINO_JSON — `signData` is the canonical JSON (UTF-8 bytes). */
  amino: 1,
  /** SIGN_MODE_DIRECT — `signData` is the protobuf-encoded SignDoc. */
  direct: 2,
  /** SIGN_MODE_TEXTUAL (rare). */
  textual: 3,
  /** ADR-036 arbitrary-message signing. */
  message: 4,
} as const;
export type CosmosDataType = (typeof CosmosDataType)[keyof typeof CosmosDataType];

export interface CosmosSignRequestProps {
  readonly requestId?: Uint8Array | string;
  /** SignDoc bytes: canonical Amino JSON (UTF-8) or protobuf SignDoc. */
  readonly signData: Uint8Array;
  readonly dataType: CosmosDataType;
  /** Full signing path, e.g. `m/44'/118'/0'/0/0`. */
  readonly path: string;
  readonly xfp: string | number;
  /** Bech32 signer address — device display. */
  readonly address?: string;
  readonly origin?: string;
}

/**
 * Ethermint-family chains (Injective, Evmos, Dymension, …) sign with
 * keccak-256 over Ethereum-style keys (`m/44'/60'/...`) and travel as an
 * `evm-sign-request` instead.
 */
export interface EthermintSignRequestProps {
  readonly requestId?: Uint8Array | string;
  readonly signData: Uint8Array;
  /** Amino or Direct — the SignDoc encoding. */
  readonly dataType: typeof CosmosDataType.amino | typeof CosmosDataType.direct;
  /** e.g. `m/44'/60'/0'/0/0`. */
  readonly path: string;
  readonly xfp: string | number;
  /** The `0x…` signer address string — travels as its ASCII bytes on this wire. */
  readonly address?: string;
  readonly origin?: string;
}

export interface CosmosSignatureResult {
  readonly requestId: Uint8Array;
  /** 64-byte compact secp256k1 signature (r || s). */
  readonly signature: Uint8Array;
  /** 33-byte compressed public key (absent on the `evm-signature` reply shape). */
  readonly publicKey: Uint8Array | undefined;
}

const COSMOS_REPLY_TYPES = ['cosmos-signature'] as const;
const ETHERMINT_REPLY_TYPES = ['evm-signature'] as const;

/** EvmSignDataType on the wire: 2 = Amino SignDoc, 3 = Direct SignDoc. */
const ETHERMINT_WIRE_TYPE: Record<number, number> = { 1: 2, 2: 3 };

export class CosmosChain {
  static readonly DataType = CosmosDataType;

  private readonly context: ChainContext;

  constructor(config?: EraConnectConfig) {
    this.context = resolveContext(config);
  }

  /** Build a `cosmos-sign-request` (4101). Reply: `cosmos-signature` (4102). */
  generateSignRequest(props: CosmosSignRequestProps): SignRequest<CosmosSignatureResult> {
    const requestId = resolveRequestId(this.context, props.requestId);
    const path = parsePath(props.path);
    const xfp = normalizeXfp(props.xfp);
    if (props.signData.length === 0) {
      throw new EraSdkError('invalid-props', 'signData must not be empty');
    }

    const entries: [number, CborValue][] = [
      [1, cbTag(37, cbBytes(requestId))],
      [2, cbBytes(props.signData)],
      [3, cbUint(props.dataType)],
      [4, cbArray([keypath304(path, xfp)])],
    ];
    if (props.address !== undefined) entries.push([5, cbArray([cbText(props.address)])]);
    entries.push([6, cbText(props.origin ?? this.context.origin)]);

    const ur = new UrValue('cosmos-sign-request', cborEncode(cbMap(entries)));
    return makeSignRequest({
      ur,
      requestId,
      replyTypes: COSMOS_REPLY_TYPES,
      context: this.context,
      parse: (reply) => parseCosmosSignature(reply, requestId, [...COSMOS_REPLY_TYPES]),
    });
  }

  /**
   * Build an `evm-sign-request` (4101, the Ethermint shape) for
   * Injective/Evmos/Dymension-style chains. Reply: `evm-signature` (4102).
   * The digest on these chains is keccak-256 — see `verifyCosmosSignature`.
   */
  generateEthermintSignRequest(
    props: EthermintSignRequestProps,
  ): SignRequest<CosmosSignatureResult> {
    const requestId = resolveRequestId(this.context, props.requestId);
    const path = parsePath(props.path);
    const xfp = normalizeXfp(props.xfp);
    if (props.signData.length === 0) {
      throw new EraSdkError('invalid-props', 'signData must not be empty');
    }
    const wireType = ETHERMINT_WIRE_TYPE[props.dataType];
    if (wireType === undefined) {
      throw new EraSdkError('invalid-props', 'Ethermint requests are Amino or Direct only');
    }

    const entries: [number, CborValue][] = [
      [1, cbTag(37, cbBytes(requestId))],
      [2, cbBytes(props.signData)],
      [3, cbUint(wireType)],
      [4, cbUint(0)], // customChainId — 0, the chain resolves from the SignDoc
      [5, keypath304(path, xfp)],
    ];
    if (props.address !== undefined) {
      entries.push([6, cbBytes(utf8Encode(props.address))]); // ASCII of the 0x string
    }
    entries.push([7, cbText(props.origin ?? this.context.origin)]);

    const ur = new UrValue('evm-sign-request', cborEncode(cbMap(entries)));
    return makeSignRequest({
      ur,
      requestId,
      replyTypes: ETHERMINT_REPLY_TYPES,
      context: this.context,
      parse: (reply) => parseCosmosSignature(reply, requestId, [...ETHERMINT_REPLY_TYPES]),
    });
  }

  /** Parse a `cosmos-signature`/`evm-signature` standalone. */
  parseSignature(input: Ur | string, expect?: ExpectedReply): CosmosSignatureResult {
    return parseCosmosSignature(
      toUr(input),
      expect?.requestId === undefined ? undefined : normalizeRequestId(expect.requestId),
      ['cosmos-signature', 'evm-signature'],
    );
  }
}

function parseCosmosSignature(
  ur: Ur,
  expectedRequestId: Uint8Array | undefined,
  replyTypes: string[],
): CosmosSignatureResult {
  requireUrType(ur, replyTypes, 'cosmos-signature');
  const map = requireReplyMap(ur, ur.type);
  const requestId = requireRequestIdEcho(map, 1, expectedRequestId, ur.type);
  const signature = asBytes(mapGet(map, 2));
  if (!signature || signature.length !== 64) {
    throw new EraSdkError(
      'malformed-reply',
      `${ur.type} signature is ${signature?.length ?? 0} bytes, expected 64 (compact r||s)`,
    );
  }
  const publicKey = asBytes(mapGet(map, 3));
  if (publicKey !== undefined && publicKey.length !== 33) {
    throw new EraSdkError('malformed-reply', `${ur.type} public key is not 33 bytes`);
  }
  return { requestId, signature, publicKey };
}
