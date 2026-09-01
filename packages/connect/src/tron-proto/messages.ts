import { hexToBytes, utf8Decode } from '../core/bytes';
import { EraSdkError } from '../core/errors';
import { firstBytes, ProtoWriter, readFields } from './wire';

/**
 * The Tron signing envelope ("QrCode Protocol"):
 * `Base -> Payload -> SignTransaction -> TronTx`, gzip-compressed and wrapped
 * in a `keystone-sign-request` (6101) CBOR map. Schemas are vendored under
 * `proto/tron/`; this codec hand-writes the five messages the wallet side
 * speaks, with reference-exact field emission (explicitly-set defaults ARE
 * written; ascending field order).
 */

export interface TronLatestBlock {
  /** FULL 64-hex block id of a live now-block (the device slices ref_block_hash from it). */
  readonly hash: string;
  readonly number: number;
  readonly timestamp: number;
}

export interface TronSignRequestProto {
  /** Lowercase, ZERO-PADDED 8-hex source fingerprint (the wire demands the string form). */
  readonly xfpHex: string;
  /** Hyphenated UUID string; echoed by the device as the only reply binding. */
  readonly signId: string;
  readonly hdPath: string;
  readonly timestamp: number;
  readonly decimals: number;
  readonly token: string;
  readonly contractAddress?: string | undefined;
  readonly from?: string | undefined;
  readonly to?: string | undefined;
  readonly memo?: string | undefined;
  readonly value?: string | undefined;
  readonly fee?: number | undefined;
  readonly latestBlock: TronLatestBlock;
  /** Serialized `Transaction.raw_data` — the signing source of truth. */
  readonly rawData: Uint8Array;
}

const PAYLOAD_TYPE_SIGN_TX = 2;

export function encodeSignRequestProto(req: TronSignRequestProto): Uint8Array {
  if (req.fee !== undefined && (req.fee < 0 || req.fee > 0x7fffffff)) {
    throw new EraSdkError('invalid-props', 'tron fee must fit a positive int32');
  }
  const latestBlock = new ProtoWriter()
    .stringField(1, req.latestBlock.hash)
    .varintField(2, req.latestBlock.number)
    .varintField(3, req.latestBlock.timestamp)
    .finish();

  const tronTx = new ProtoWriter().stringField(1, req.token);
  if (req.contractAddress !== undefined) tronTx.stringField(2, req.contractAddress);
  if (req.from !== undefined) tronTx.stringField(3, req.from);
  if (req.to !== undefined) tronTx.stringField(4, req.to);
  if (req.memo !== undefined) tronTx.stringField(5, req.memo);
  if (req.value !== undefined) tronTx.stringField(6, req.value);
  tronTx.messageField(7, latestBlock);
  if (req.fee !== undefined) tronTx.varintField(9, req.fee);
  tronTx.bytesField(10, req.rawData);

  const signTx = new ProtoWriter()
    .stringField(1, 'TRON')
    .stringField(2, req.signId)
    .stringField(3, req.hdPath)
    .varintField(4, req.timestamp)
    .varintField(5, req.decimals)
    .messageField(8, tronTx.finish())
    .finish();

  const payload = new ProtoWriter()
    .varintField(1, PAYLOAD_TYPE_SIGN_TX)
    .stringField(2, req.xfpHex)
    .messageField(4, signTx)
    .finish();

  return new ProtoWriter()
    .varintField(1, 2) // Base.version
    .stringField(2, 'QrCode Protocol')
    .messageField(3, payload)
    .finish();
}

export interface TronSignResultProto {
  readonly signId: string;
  readonly txId: string;
  readonly rawTx: string;
}

/** Parse a `keystone-sign-result` Base protobuf. Unknown fields are skipped. */
export function decodeSignResultProto(bytes: Uint8Array): TronSignResultProto {
  const base = readFields(bytes);
  const payloadBytes = firstBytes(base, 3);
  if (!payloadBytes) {
    throw new EraSdkError('malformed-reply', 'keystone-sign-result carries no payload');
  }
  const payload = readFields(payloadBytes);
  const resultBytes = firstBytes(payload, 7); // Payload.signTxResult
  if (!resultBytes) {
    return { signId: '', txId: '', rawTx: '' };
  }
  const result = readFields(resultBytes);
  return {
    signId: text(firstBytes(result, 1)),
    txId: text(firstBytes(result, 2)),
    rawTx: text(firstBytes(result, 3)),
  };
}

function text(bytes: Uint8Array | null): string {
  if (!bytes) return '';
  try {
    return utf8Decode(bytes);
  } catch {
    throw new EraSdkError('malformed-reply', 'protobuf string field is not valid UTF-8');
  }
}

export interface SignedTronTx {
  /** Verbatim `raw_data` slice — the digest is sha256 over the device's own serialization. */
  readonly rawData: Uint8Array;
  readonly signatures: readonly Uint8Array[];
}

/**
 * Split a signed Tron network `Transaction` frame (`{1: raw_data, 2: signature*}`)
 * from the reply's `rawTx` hex. Top-level fields must be length-delimited —
 * anything else is not a transaction frame.
 */
export function splitSignedTronTx(rawTxHex: string): SignedTronTx {
  let frame: Uint8Array;
  try {
    frame = hexToBytes(rawTxHex);
  } catch {
    throw new EraSdkError('malformed-reply', 'signed Tron transaction is not hex');
  }
  const fields = readFields(frame);
  let rawData: Uint8Array | null = null;
  const signatures: Uint8Array[] = [];
  for (const f of fields) {
    if (f.wireType !== 2) {
      throw new EraSdkError('malformed-reply', 'unexpected wire type in signed Tron transaction');
    }
    if (f.field === 1 && rawData === null) rawData = f.bytes;
    if (f.field === 2) signatures.push(f.bytes);
  }
  if (rawData === null) {
    throw new EraSdkError('malformed-reply', 'signed Tron transaction carries no raw_data');
  }
  return { rawData, signatures };
}
