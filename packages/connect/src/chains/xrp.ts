import { cborDecode } from '../cbor/decode';
import { cborEncode } from '../cbor/encode';
import { asBytes, cbBytes } from '../cbor/model';
import { utf8Encode } from '../core/bytes';
import { EraSdkError } from '../core/errors';
import type { Ur } from '../ur/ur';
import { Ur as UrValue } from '../ur/ur';
import type { ChainContext, EraConnectConfig, SignRequest } from './shared';
import { makeSignRequest, requireUrType, resolveContext, toUr } from './shared';

/**
 * XRP rides the XRP Toolkit convention: an untyped `ur:bytes` whose CBOR
 * payload is the transaction JSON (request) or the canonical signed XRPL
 * binary (reply). There is NO request id and NO chain-specific UR type — the
 * content itself is the only binding, which is why `verifyXrpSignature`
 * (from `@hwlt/era-connect/verify`) is not optional on this chain.
 */
export interface XrpSignRequestProps {
  /**
   * The unsigned transaction JSON. MUST already carry `SigningPubKey` (the
   * device signs with `m/44'/144'/0'/0/0` — put THAT key's hex here),
   * `TransactionType`, a classic `r…` `Account`, `Fee` and `Sequence`.
   */
  readonly transaction: Record<string, unknown> | string;
}

export interface XrpSignatureResult {
  /** The canonical signed XRPL binary transaction — submit it verbatim. */
  readonly signedTx: Uint8Array;
}

const REPLY_TYPES = ['bytes'] as const;

export class XrpChain {
  private readonly context: ChainContext;

  constructor(config?: EraConnectConfig) {
    this.context = resolveContext(config);
  }

  /** Wrap the tx JSON in the `ur:bytes` request shape. Reply: `ur:bytes` with the signed binary. */
  generateSignRequest(props: XrpSignRequestProps): SignRequest<XrpSignatureResult> {
    const text =
      typeof props.transaction === 'string' ? props.transaction : JSON.stringify(props.transaction);
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(text) as Record<string, unknown>;
    } catch {
      throw new EraSdkError('invalid-props', 'transaction is not valid JSON');
    }
    // Mirror the device's own acceptance gate so a refusal happens HERE with
    // a reason, not silently on the hardware.
    if (typeof parsed.TransactionType !== 'string') {
      throw new EraSdkError('invalid-props', 'transaction needs a TransactionType');
    }
    if (typeof parsed.Account !== 'string' || !parsed.Account.startsWith('r')) {
      throw new EraSdkError('invalid-props', 'transaction needs a classic r… Account');
    }
    if (typeof parsed.SigningPubKey !== 'string' || parsed.SigningPubKey.length === 0) {
      throw new EraSdkError(
        'invalid-props',
        "transaction needs SigningPubKey — the device signs with m/44'/144'/0'/0/0",
      );
    }
    if (parsed.Fee === undefined || parsed.Sequence === undefined) {
      throw new EraSdkError('invalid-props', 'transaction needs Fee and Sequence');
    }

    const ur = new UrValue('bytes', cborEncode(cbBytes(utf8Encode(text))));
    return makeSignRequest({
      ur,
      replyTypes: REPLY_TYPES,
      context: this.context,
      parse: (reply) => this.parseSignature(reply),
    });
  }

  /** Parse the `ur:bytes` reply into the signed binary transaction. */
  parseSignature(input: Ur | string): XrpSignatureResult {
    const ur = toUr(input);
    requireUrType(ur, [...REPLY_TYPES], 'xrp reply');
    let decoded: ReturnType<typeof cborDecode>;
    try {
      decoded = cborDecode(ur.cbor);
    } catch (e) {
      throw new EraSdkError('malformed-cbor', `xrp reply: ${(e as Error).message}`);
    }
    const bytes = asBytes(decoded);
    if (!bytes || bytes.length === 0) {
      throw new EraSdkError('malformed-reply', 'xrp reply carries no signed transaction bytes');
    }
    return { signedTx: bytes };
  }
}
