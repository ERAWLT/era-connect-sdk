import { cborEncode } from '../cbor/encode';
import { asBytes, cbBytes, cbMap, cbText, mapGet } from '../cbor/model';
import { bytesToHex } from '../core/bytes';
import { EraSdkError } from '../core/errors';
import { normalizeRequestId, uuidStringify } from '../core/rand';
import { normalizeXfp, parsePath, xfpToHex } from '../registry/keypath';
import { gunzipCapped, gzipCompress } from '../tron-proto/gzip';
import type { BchProtoInput, BchProtoOutput } from '../tron-proto/messages';
import { decodeSignResultProto, encodeBchSignRequestProto } from '../tron-proto/messages';
import type { Ur } from '../ur/ur';
import { Ur as UrValue } from '../ur/ur';
import { decodeCashAddr, encodeCashAddr } from './cashaddr';
import type { ChainContext, EraConnectConfig, ExpectedReply, SignRequest } from './shared';
import {
  makeSignRequest,
  requireReplyMap,
  requireUrType,
  resolveContext,
  resolveRequestId,
  toUr,
} from './shared';

export type { CashAddrPayload, CashAddrType } from './cashaddr';
export { CASHADDR_PREFIX, decodeCashAddr, encodeCashAddr } from './cashaddr';

/** One UTXO the transaction spends. P2PKH only — that is what the device signs. */
export interface BchTxInput {
  /** Display-order (big-endian) txid of the UTXO, 64 hex chars. */
  readonly txid: string;
  /** Output index of the UTXO. */
  readonly index: number;
  /** UTXO value in satoshis — part of the BIP-143 sighash, so it MUST be exact. */
  readonly value: number | bigint;
  /** The compressed (33-byte) public key that owns the UTXO. */
  readonly publicKey: Uint8Array | string;
  /** Full derivation path of that key, e.g. `m/44'/145'/0'/0/0`. */
  readonly path: string;
}

export interface BchTxOutput {
  /** CashAddr (P2PKH or P2SH), with or without the `bitcoincash:` prefix. */
  readonly address: string;
  /** Output value in satoshis. */
  readonly value: number | bigint;
  /** Marks the output as change on the device screen. Display only. */
  readonly isChange?: boolean;
  /** Shown with the change output; the address above is still what is paid. */
  readonly changeAddressPath?: string;
}

export interface BchSignRequestProps {
  readonly requestId?: Uint8Array | string;
  readonly inputs: readonly BchTxInput[];
  /** Every output — change included — carries a real CashAddr. */
  readonly outputs: readonly BchTxOutput[];
  /** Fee in satoshis. Must equal `sum(inputs) - sum(outputs)` exactly. */
  readonly fee: number | bigint;
  /** Dust threshold shown on the device; defaults to 546. */
  readonly dustThreshold?: number;
  readonly memo?: string;
  readonly xfp: string | number;
  /** Milliseconds timestamp shown in the device log; 0 omits it. */
  readonly timestamp?: number;
  readonly origin?: string;
}

export interface BchSignatureResult {
  readonly requestId: Uint8Array;
  /** Display-order txid of the signed transaction, as computed by the device. */
  readonly txId: string;
  /** Hex of the fully signed transaction — broadcast as-is. */
  readonly rawTx: string;
}

const MAX_COMPRESSED_BYTES = 8 * 1024;
const MAX_INFLATED_BYTES = 64 * 1024;

const REPLY_TYPES = ['keystone-sign-result'] as const;

/** Satoshi amounts must stay exact in a double; anything above is refused. */
const MAX_SATOSHI = 2_100_000_000_000_000n; // 21M coins

function toSatoshi(value: number | bigint, label: string): bigint {
  // Refuse non-integers BEFORE BigInt() — BigInt(NaN) throws a raw RangeError.
  if (typeof value === 'number' && !Number.isSafeInteger(value)) {
    throw new EraSdkError('invalid-props', `${label} must be an integer satoshi amount`);
  }
  const v = typeof value === 'number' ? BigInt(value) : value;
  if (v <= 0n || v > MAX_SATOSHI) {
    throw new EraSdkError('invalid-props', `${label} must be a positive satoshi amount`);
  }
  return v;
}

function toPublicKeyHex(publicKey: Uint8Array | string, label: string): string {
  const hex = typeof publicKey === 'string' ? publicKey.toLowerCase() : bytesToHex(publicKey);
  if (!/^0[23][0-9a-f]{64}$/.test(hex)) {
    throw new EraSdkError('invalid-props', `${label} must be a 33-byte compressed public key`);
  }
  return hex;
}

/**
 * Bitcoin Cash signing rides the structured `keystone-sign-request` (6101)
 * envelope, NOT the PSBT path: the device's PSBT signer cannot apply the
 * `SIGHASH_FORKID` (0x41) sighash BCH consensus requires, so a dedicated
 * FORKID signer sits behind this envelope instead. The SDK therefore builds
 * the transaction container from structured inputs/outputs here — the one
 * chain where it is more than a transport.
 *
 * The device derives each input's signing key from its `path`, computes the
 * BIP-143 sighash with FORKID over version-1/locktime-0/sequence-0xfffffffd
 * legacy serialization, and returns the COMPLETE signed transaction.
 */
export class BchChain {
  private readonly context: ChainContext;

  constructor(config?: EraConnectConfig) {
    this.context = resolveContext(config);
  }

  /** Build a `keystone-sign-request` (6101). Reply: `keystone-sign-result` (6102). */
  generateSignRequest(props: BchSignRequestProps): SignRequest<BchSignatureResult> {
    const requestId = resolveRequestId(this.context, props.requestId);
    const xfp = normalizeXfp(props.xfp);
    if (props.inputs.length === 0) {
      throw new EraSdkError('invalid-props', 'at least one input is required');
    }
    if (props.outputs.length === 0) {
      throw new EraSdkError('invalid-props', 'at least one output is required');
    }

    let inputSum = 0n;
    const inputs: BchProtoInput[] = props.inputs.map((input, i) => {
      if (!/^[0-9a-fA-F]{64}$/.test(input.txid)) {
        throw new EraSdkError('invalid-props', `input ${i}: txid must be 64 hex chars`);
      }
      if (!Number.isInteger(input.index) || input.index < 0) {
        throw new EraSdkError('invalid-props', `input ${i}: index must be a non-negative integer`);
      }
      parsePath(input.path); // validate shape; the wire carries the string form
      const value = toSatoshi(input.value, `input ${i} value`);
      inputSum += value;
      return {
        txidHex: input.txid.toLowerCase(),
        index: input.index,
        value,
        publicKeyHex: toPublicKeyHex(input.publicKey, `input ${i} publicKey`),
        ownerKeyPath: input.path,
      };
    });

    let outputSum = 0n;
    const outputs: BchProtoOutput[] = props.outputs.map((output, i) => {
      // Decode AND re-encode: the wire must carry the canonical lowercase
      // form. The device's own parser prepends a lowercase prefix before
      // decoding, so the spec's all-uppercase (QR alphanumeric) spelling
      // turns mixed-case there, is rejected — and the rejection FAILS OPEN
      // into a zero pubkey hash, i.e. a signed burn output. Never forward
      // the caller's spelling.
      const decoded = decodeCashAddr(output.address);
      const value = toSatoshi(output.value, `output ${i} value`);
      outputSum += value;
      if (output.changeAddressPath !== undefined) parsePath(output.changeAddressPath);
      return {
        address: encodeCashAddr(decoded.type, decoded.hash, {
          withPrefix: output.address.includes(':'),
        }),
        value,
        isChange: output.isChange ?? false,
        changeAddressPath: output.changeAddressPath,
      };
    });

    // The fee field is what the device SHOWS the user, but the fee the network
    // takes is inputs minus outputs — an inconsistent pair would put a lie on
    // the confirmation screen, so it is refused here.
    const fee = toSatoshi(props.fee, 'fee');
    if (inputSum !== outputSum + fee) {
      throw new EraSdkError(
        'invalid-props',
        `fee mismatch: inputs (${inputSum}) minus outputs (${outputSum}) is ${
          inputSum - outputSum
        }, but fee says ${fee}`,
      );
    }

    const dustThreshold = props.dustThreshold ?? 546;
    if (!Number.isInteger(dustThreshold) || dustThreshold < 0 || dustThreshold > 0x7fffffff) {
      throw new EraSdkError('invalid-props', 'dustThreshold must fit a non-negative int32');
    }

    const proto = encodeBchSignRequestProto({
      // Zero-padded to eight characters — same firmware hex reader as Tron.
      xfpHex: xfpToHex(xfp),
      signId: uuidStringify(requestId),
      timestamp: props.timestamp ?? 0,
      fee,
      dustThreshold,
      memo: props.memo,
      inputs,
      outputs,
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
      parse: (reply) => parseBchSignature(reply, requestId),
    });
  }

  /**
   * Parse a `keystone-sign-result` standalone. The request id lives INSIDE
   * the protobuf (`signId`); pass `expect.requestId` to enable the echo
   * check — prefer `SignRequest.scanner().parse()`.
   */
  parseSignature(input: Ur | string, expect?: ExpectedReply): BchSignatureResult {
    return parseBchSignature(
      toUr(input),
      expect?.requestId === undefined ? undefined : normalizeRequestId(expect.requestId),
    );
  }
}

function parseBchSignature(ur: Ur, expectedRequestId: Uint8Array | undefined): BchSignatureResult {
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

  // The signId echo is the ONLY anti-replay binding on this envelope. After
  // it, ALWAYS run `verifyBchSignedTx` from `@hwlt/era-connect/verify` — the
  // reply is a complete broadcastable transaction, and the echo alone does
  // not prove its inputs and outputs are the ones that were requested.
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
  if (!/^[0-9a-fA-F]+$/.test(result.rawTx) || result.rawTx.length % 2 !== 0) {
    throw new EraSdkError('malformed-reply', 'keystone-sign-result rawTx is not hex');
  }
  const requestId = expectedRequestId ?? signIdToBytes(result.signId);
  return { requestId, txId: result.txId, rawTx: result.rawTx };
}

function signIdToBytes(signId: string): Uint8Array {
  try {
    return normalizeRequestId(signId);
  } catch {
    return new Uint8Array(16);
  }
}
