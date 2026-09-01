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

export interface BchProtoInput {
  /** Display-order (big-endian) txid, 64 hex chars — a STRING on the wire. */
  readonly txidHex: string;
  readonly index: number;
  /** UTXO value in satoshis. */
  readonly value: bigint;
  /** Compressed public key, 66 hex chars — a STRING on the wire. */
  readonly publicKeyHex: string;
  /** Full derivation path of the key that owns the UTXO. */
  readonly ownerKeyPath: string;
}

export interface BchProtoOutput {
  /** CashAddr (verbatim; the device accepts both prefixed and bare form). */
  readonly address: string;
  readonly value: bigint;
  readonly isChange: boolean;
  readonly changeAddressPath?: string | undefined;
}

export interface BchSignRequestProto {
  /** Lowercase, ZERO-PADDED 8-hex source fingerprint (the wire demands the string form). */
  readonly xfpHex: string;
  /** Hyphenated UUID string; echoed by the device as the only reply binding. */
  readonly signId: string;
  readonly timestamp: number;
  /** Fee in satoshis — shown on the device; MUST equal inputs minus outputs. */
  readonly fee: bigint;
  readonly dustThreshold: number;
  readonly memo?: string | undefined;
  readonly inputs: readonly BchProtoInput[];
  readonly outputs: readonly BchProtoOutput[];
}

/**
 * The BCH leg of the same envelope: `Base -> Payload -> SignTransaction ->
 * BchTx` at oneof tag 10, with FLAT inputs (value/publicKey are direct
 * fields, no nested Utxo sub-message). Unlike the Tron writer, default
 * values are OMITTED here — proto3 emission, which is what the reference
 * wallet capture the firmware fixture pins does. `hdPath` (SignTransaction
 * field 3) is deliberately absent: the reference never sends it and the
 * device reads the per-input `ownerKeyPath` instead.
 */
export function encodeBchSignRequestProto(req: BchSignRequestProto): Uint8Array {
  const bchTx = new ProtoWriter();
  if (req.fee !== 0n) bchTx.varintField(1, req.fee);
  if (req.dustThreshold !== 0) bchTx.varintField(2, req.dustThreshold);
  if (req.memo !== undefined && req.memo !== '') bchTx.stringField(3, req.memo);
  for (const input of req.inputs) {
    const w = new ProtoWriter().stringField(1, input.txidHex);
    if (input.index !== 0) w.varintField(2, input.index);
    if (input.value !== 0n) w.varintField(3, input.value);
    w.stringField(4, input.publicKeyHex);
    w.stringField(5, input.ownerKeyPath);
    bchTx.messageField(4, w.finish());
  }
  for (const output of req.outputs) {
    const w = new ProtoWriter().stringField(1, output.address);
    if (output.value !== 0n) w.varintField(2, output.value);
    if (output.isChange) w.varintField(3, 1);
    if (output.changeAddressPath !== undefined && output.changeAddressPath !== '') {
      w.stringField(4, output.changeAddressPath);
    }
    bchTx.messageField(5, w.finish());
  }

  const signTx = new ProtoWriter().stringField(1, 'BCH').stringField(2, req.signId);
  if (req.timestamp !== 0) signTx.varintField(4, req.timestamp);
  signTx.varintField(5, 8); // decimal: BCH is always 8
  signTx.messageField(10, bchTx.finish());

  const payload = new ProtoWriter()
    .varintField(1, PAYLOAD_TYPE_SIGN_TX)
    .stringField(2, req.xfpHex)
    .messageField(4, signTx.finish())
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
