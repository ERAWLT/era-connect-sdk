import { blake2b } from '@noble/hashes/blake2b';
import { cborEncode } from '../cbor/encode';
import type { CborValue } from '../cbor/model';
import { asBytes, cbArray, cbBytes, cbMap, cbTag, cbText, mapGet } from '../cbor/model';
import { bytesToHex, hexToBytes } from '../core/bytes';
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

export interface SuiSignRequestProps {
  readonly requestId?: Uint8Array | string;
  /**
   * The COMPLETE BCS intent message (intent prefix + transaction bytes) as
   * your Sui tooling produces it — the device signs BLAKE2b-256 of exactly
   * these bytes.
   */
  readonly intentMessage: Uint8Array;
  /** Fully hardened SLIP-10 path, e.g. `m/44'/784'/0'/0'/0'`. */
  readonly path: string;
  readonly xfp: string | number;
  /** 32-byte Sui address (raw or `0x` hex) — device display. */
  readonly address?: Uint8Array | string;
  readonly origin?: string;
}

export interface SuiSignHashRequestProps {
  readonly requestId?: Uint8Array | string;
  /** The 32-byte digest to sign directly (the hash-request variant). */
  readonly messageHash: Uint8Array;
  readonly path: string;
  readonly xfp: string | number;
  readonly address?: Uint8Array | string;
  readonly origin?: string;
}

export interface SuiSignatureResult {
  readonly requestId: Uint8Array;
  /** 64-byte Ed25519 signature. */
  readonly signature: Uint8Array;
  /** The 32-byte signer public key the device answered with. */
  readonly publicKey: Uint8Array;
}

const REPLY_TYPES = ['sui-signature'] as const;

export class SuiChain {
  private readonly context: ChainContext;

  constructor(config?: EraConnectConfig) {
    this.context = resolveContext(config);
  }

  /** Build a `sui-sign-request` (7101). Reply: `sui-signature` (7102). */
  generateSignRequest(props: SuiSignRequestProps): SignRequest<SuiSignatureResult> {
    if (props.intentMessage.length === 0) {
      throw new EraSdkError('invalid-props', 'intentMessage must not be empty');
    }
    return this.build('sui-sign-request', cbBytes(props.intentMessage), props);
  }

  /** Build a `sui-sign-hash-request` (7103) — signs the given 32-byte digest directly. */
  generateSignHashRequest(props: SuiSignHashRequestProps): SignRequest<SuiSignatureResult> {
    if (props.messageHash.length !== 32) {
      throw new EraSdkError('invalid-props', 'messageHash must be 32 bytes');
    }
    // The hash travels as a HEX STRING on this variant (device contract).
    return this.build('sui-sign-hash-request', cbText(bytesToHex(props.messageHash)), props);
  }

  private build(
    urType: string,
    signData: CborValue,
    props: Omit<SuiSignRequestProps, 'intentMessage'> & { address?: Uint8Array | string },
  ): SignRequest<SuiSignatureResult> {
    const requestId = resolveRequestId(this.context, props.requestId);
    const path = parsePath(props.path);
    if (!path.every((level) => level.hardened)) {
      throw new EraSdkError(
        'invalid-props',
        `Sui signing paths are fully hardened (SLIP-10 Ed25519), got ${props.path}`,
      );
    }
    const xfp = normalizeXfp(props.xfp);

    const entries: [number, CborValue][] = [
      [1, cbTag(37, cbBytes(requestId))],
      [2, signData],
      [3, cbArray([keypath304(path, xfp)])],
    ];
    if (props.address !== undefined) {
      const address =
        props.address instanceof Uint8Array ? props.address : hexToBytes(props.address);
      if (address.length !== 32) {
        throw new EraSdkError('invalid-props', 'Sui address must be 32 bytes');
      }
      entries.push([4, cbArray([cbBytes(address)])]);
    }
    entries.push([5, cbText(props.origin ?? this.context.origin)]);

    const ur = new UrValue(urType, cborEncode(cbMap(entries)));
    return makeSignRequest({
      ur,
      requestId,
      replyTypes: REPLY_TYPES,
      context: this.context,
      parse: (reply) => parseSuiSignature(reply, requestId),
    });
  }

  /** Parse a `sui-signature` standalone. Prefer `SignRequest.scanner().parse()`. */
  parseSignature(input: Ur | string, expect?: ExpectedReply): SuiSignatureResult {
    return parseSuiSignature(
      toUr(input),
      expect?.requestId === undefined ? undefined : normalizeRequestId(expect.requestId),
    );
  }
}

/** BLAKE2b-256 of the intent message — the digest the device signs for `sui-sign-request`. */
export function suiIntentDigest(intentMessage: Uint8Array): Uint8Array {
  return blake2b(intentMessage, { dkLen: 32 });
}

function parseSuiSignature(ur: Ur, expectedRequestId: Uint8Array | undefined): SuiSignatureResult {
  requireUrType(ur, [...REPLY_TYPES], 'sui-signature');
  const map = requireReplyMap(ur, 'sui-signature');
  const requestId = requireRequestIdEcho(map, 1, expectedRequestId, 'sui-signature');
  const signature = asBytes(mapGet(map, 2));
  if (signature?.length !== 64) {
    throw new EraSdkError(
      'malformed-reply',
      `sui-signature signature is ${signature?.length ?? 0} bytes, expected 64`,
    );
  }
  const publicKey = asBytes(mapGet(map, 3));
  if (publicKey?.length !== 32) {
    throw new EraSdkError(
      'malformed-reply',
      'sui-signature is missing the 32-byte public key (key 3)',
    );
  }
  return { requestId, signature, publicKey };
}
