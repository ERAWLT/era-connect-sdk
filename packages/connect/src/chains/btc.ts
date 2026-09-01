import { base64 } from '@scure/base';
import { cborDecode } from '../cbor/decode';
import { cborEncode } from '../cbor/encode';
import type { CborValue } from '../cbor/model';
import { asBytes, cbArray, cbBytes, cbMap, cbTag, cbText, cbUint, mapGet } from '../cbor/model';
import { asciiDecode } from '../core/bytes';
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

export interface BtcPsbtSignRequestProps {
  /** Raw PSBT v0 bytes (BIP-174). The device's signer relies on the global UNSIGNED_TX. */
  readonly psbt: Uint8Array;
}

export interface BtcPsbtResult {
  /** The signed, NOT finalized PSBT. Finalize + broadcast with your own stack. */
  readonly psbt: Uint8Array;
}

export interface BtcMessageSignRequestProps {
  readonly requestId?: Uint8Array | string;
  readonly message: Uint8Array;
  /** Full signing path, e.g. `m/84'/0'/0'/0/0`. */
  readonly path: string;
  readonly xfp: string | number;
  /**
   * The signing address. The device's message signer supports LEGACY P2PKH
   * (`1...`) addresses only; a segwit address yields `empty-signature`.
   */
  readonly address: string;
  readonly origin?: string;
}

export interface BtcMessageSignatureResult {
  readonly requestId: Uint8Array;
  /** Raw 65-byte BIP-137 signature (header + r + s). */
  readonly signature: Uint8Array;
  /** The base64 form dApps and verifiers expect. */
  readonly signatureBase64: string;
  readonly publicKey: Uint8Array | undefined;
}

const PSBT_REPLY_TYPES = ['crypto-psbt'] as const;
const MESSAGE_REPLY_TYPES = ['btc-signature'] as const;

export class BtcChain {
  static readonly DataType = { message: 1 } as const;

  private readonly context: ChainContext;

  constructor(config?: EraConnectConfig) {
    this.context = resolveContext(config);
  }

  /**
   * Build a `crypto-psbt` (310) request: the UR payload is a bare CBOR byte
   * string of the raw PSBT — no map, no request id, no origin.
   *
   * BECAUSE the protocol carries no request id on this path, the reply is
   * bound to the request only by its content: after parsing, compare the
   * returned PSBT's unsigned transaction against the one you sent
   * (`verifySignedPsbt` from `@hwlt/era-connect/verify`). Skipping that
   * check re-opens replay of a stale signed PSBT.
   */
  generatePsbtSignRequest(props: BtcPsbtSignRequestProps): SignRequest<BtcPsbtResult> {
    if (props.psbt.length === 0) {
      throw new EraSdkError('invalid-props', 'psbt must not be empty');
    }
    const ur = new UrValue('crypto-psbt', cborEncode(cbBytes(props.psbt)));
    return makeSignRequest({
      ur,
      replyTypes: PSBT_REPLY_TYPES,
      context: this.context,
      parse: (reply) => this.parsePsbt(reply),
    });
  }

  /** Parse a `crypto-psbt` reply: the signed (not finalized) PSBT bytes. */
  parsePsbt(input: Ur | string): BtcPsbtResult {
    const ur = toUr(input);
    requireUrType(ur, [...PSBT_REPLY_TYPES], 'crypto-psbt');
    let decoded: CborValue;
    try {
      decoded = cborDecode(ur.cbor);
    } catch (e) {
      throw new EraSdkError('malformed-cbor', `crypto-psbt reply: ${(e as Error).message}`);
    }
    const bytes = asBytes(decoded);
    if (!bytes) {
      throw new EraSdkError('malformed-reply', 'crypto-psbt reply is not a byte string');
    }
    if (bytes.length === 0) {
      throw new EraSdkError('malformed-reply', 'crypto-psbt reply is empty');
    }
    return { psbt: bytes };
  }

  /** Build a `btc-sign-request` (8101) for message signing. Reply: `btc-signature` (8102). */
  generateMessageSignRequest(
    props: BtcMessageSignRequestProps,
  ): SignRequest<BtcMessageSignatureResult> {
    const requestId = resolveRequestId(this.context, props.requestId);
    const path = parsePath(props.path);
    const xfp = normalizeXfp(props.xfp);

    const ur = new UrValue(
      'btc-sign-request',
      cborEncode(
        cbMap([
          // Tag-37-wrapped on this chain (per-chain firmware policy).
          [1, cbTag(37, cbBytes(requestId))],
          [2, cbBytes(props.message)],
          [3, cbUint(BtcChain.DataType.message)],
          [4, cbArray([keypath304(path, xfp)])],
          [5, cbArray([cbText(props.address)])],
          [6, cbText(props.origin ?? this.context.origin)],
        ]),
      ),
    );
    return makeSignRequest({
      ur,
      requestId,
      replyTypes: MESSAGE_REPLY_TYPES,
      context: this.context,
      parse: (reply) => parseMessageSignature(reply, requestId),
    });
  }

  /** Parse a `btc-signature` standalone. Prefer `SignRequest.scanner().parse()`. */
  parseMessageSignature(input: Ur | string, expect?: ExpectedReply): BtcMessageSignatureResult {
    return parseMessageSignature(
      toUr(input),
      expect?.requestId === undefined ? undefined : normalizeRequestId(expect.requestId),
    );
  }
}

function parseMessageSignature(
  ur: Ur,
  expectedRequestId: Uint8Array | undefined,
): BtcMessageSignatureResult {
  requireUrType(ur, [...MESSAGE_REPLY_TYPES], 'btc-signature');
  const map = requireReplyMap(ur, 'btc-signature');
  const requestId = requireRequestIdEcho(map, 1, expectedRequestId, 'btc-signature');

  const sigValue = asBytes(mapGet(map, 2));
  if (sigValue === undefined) {
    throw new EraSdkError('malformed-reply', 'btc-signature is missing the signature (key 2)');
  }
  // The device answers a message request for an address its signer cannot
  // handle (any non-legacy script type) with an EMPTY signature.
  if (sigValue.length === 0) {
    throw new EraSdkError(
      'empty-signature',
      'the device returned an empty signature — Bitcoin message signing supports legacy P2PKH (1...) addresses only',
    );
  }

  // Device quirk: the reply bytes are the ASCII of a base64 string, not raw
  // signature bytes. Decode twice; tolerate a firmware that starts sending
  // raw 65-byte signatures directly.
  let signature: Uint8Array;
  try {
    signature = base64.decode(asciiDecode(sigValue));
  } catch {
    signature = sigValue;
  }
  if (signature.length !== 65) {
    if (sigValue.length === 65) {
      signature = sigValue;
    } else {
      throw new EraSdkError(
        'malformed-reply',
        `btc-signature payload does not decode to a 65-byte BIP-137 signature (${sigValue.length} bytes on the wire)`,
      );
    }
  }
  return {
    requestId,
    signature,
    signatureBase64: base64.encode(signature),
    publicKey: asBytes(mapGet(map, 3)),
  };
}
