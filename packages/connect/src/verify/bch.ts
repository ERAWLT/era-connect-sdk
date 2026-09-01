import { secp256k1 } from '@noble/curves/secp256k1';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { sha256 } from '@noble/hashes/sha2';
import { decodeCashAddr } from '../chains/cashaddr';
import { bytesToHex, concatBytes, equalBytes, hexToBytes } from '../core/bytes';
import { EraSdkError } from '../core/errors';
import type { VerifyResult } from './result';
import { failed, verified } from './result';

/**
 * "The device signed exactly what I sent" for Bitcoin Cash.
 *
 * The reply on this chain is a COMPLETE broadcastable transaction, so the
 * binding has to be rebuilt from it: every outpoint, every output script and
 * value, and every input signature are checked against the request. The
 * sighash is BIP-143 with `SIGHASH_FORKID` (0x41) — recomputed here from the
 * request's own input values, which is also what makes a value lie visible:
 * a wrong `value` in the request would fail right here, because the network
 * would reject the same preimage.
 */

export interface VerifyBchInput {
  /** Display-order txid, 64 hex chars — as sent in the request. */
  readonly txid: string;
  readonly index: number;
  /** UTXO value in satoshis — as sent in the request. */
  readonly value: number | bigint;
  /** The compressed public key the request named as the UTXO owner. */
  readonly publicKey: Uint8Array | string;
}

export interface VerifyBchOutput {
  /** CashAddr as sent in the request (prefixed or bare). */
  readonly address: string;
  readonly value: number | bigint;
}

export interface VerifyBchSignedTxArgs {
  /** The reply's `rawTx` hex. */
  readonly rawTx: string;
  readonly inputs: readonly VerifyBchInput[];
  readonly outputs: readonly VerifyBchOutput[];
  /** The reply's `txId`, when you want it checked against the raw bytes too. */
  readonly txId?: string;
}

const SIGHASH_FORKID_ALL = 0x41;
// The device's signer hardcodes these; a reply that deviates was not built
// by it (or a firmware change landed — then update BOTH constants and docs).
const BCH_TX_VERSION = 1;
const BCH_TX_LOCKTIME = 0;
const BCH_TX_SEQUENCE = 0xfffffffd;

interface DecodedInput {
  readonly txidLE: Uint8Array;
  readonly index: number;
  readonly scriptSig: Uint8Array;
  readonly sequence: number;
}

interface DecodedOutput {
  readonly value: bigint;
  readonly script: Uint8Array;
}

export interface DecodedBchTx {
  readonly version: number;
  readonly inputs: readonly DecodedInput[];
  readonly outputs: readonly DecodedOutput[];
  readonly locktime: number;
}

/** Hardened reader for the legacy (non-witness) transaction serialization. */
export function decodeBchRawTx(rawTxHex: string): DecodedBchTx {
  let bytes: Uint8Array;
  try {
    bytes = hexToBytes(rawTxHex);
  } catch {
    throw new EraSdkError('malformed-reply', 'signed transaction is not hex');
  }
  let offset = 0;
  const need = (n: number): void => {
    if (offset + n > bytes.length) {
      throw new EraSdkError('malformed-reply', 'signed transaction is truncated');
    }
  };
  const readU32 = (): number => {
    need(4);
    const v =
      bytes[offset]! |
      (bytes[offset + 1]! << 8) |
      (bytes[offset + 2]! << 16) |
      (bytes[offset + 3]! << 24);
    offset += 4;
    return v >>> 0;
  };
  const readU64 = (): bigint => {
    need(8);
    let v = 0n;
    for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(bytes[offset + i]!);
    offset += 8;
    return v;
  };
  const readVarint = (): number => {
    need(1);
    const first = bytes[offset++]!;
    if (first < 0xfd) return first;
    if (first === 0xfd) {
      need(2);
      const v = bytes[offset]! | (bytes[offset + 1]! << 8);
      offset += 2;
      return v;
    }
    // 4- and 8-byte counts cannot occur in a transaction the device can build.
    throw new EraSdkError('malformed-reply', 'unreasonable varint in signed transaction');
  };
  const readSlice = (n: number): Uint8Array => {
    need(n);
    const s = bytes.subarray(offset, offset + n);
    offset += n;
    return s;
  };

  const version = readU32();
  const inputCount = readVarint();
  if (inputCount === 0 || inputCount > 1000) {
    throw new EraSdkError('malformed-reply', 'unreasonable input count in signed transaction');
  }
  const inputs: DecodedInput[] = [];
  for (let i = 0; i < inputCount; i++) {
    const txidLE = readSlice(32);
    const index = readU32();
    const scriptSig = readSlice(readVarint());
    const sequence = readU32();
    inputs.push({ txidLE, index, scriptSig, sequence });
  }
  const outputCount = readVarint();
  if (outputCount === 0 || outputCount > 1000) {
    throw new EraSdkError('malformed-reply', 'unreasonable output count in signed transaction');
  }
  const outputs: DecodedOutput[] = [];
  for (let i = 0; i < outputCount; i++) {
    const value = readU64();
    const script = readSlice(readVarint());
    outputs.push({ value, script });
  }
  const locktime = readU32();
  if (offset !== bytes.length) {
    throw new EraSdkError('malformed-reply', 'trailing bytes after signed transaction');
  }
  return { version, inputs, outputs, locktime };
}

function sha256d(data: Uint8Array): Uint8Array {
  return sha256(sha256(data));
}

function hash160(data: Uint8Array): Uint8Array {
  return ripemd160(sha256(data));
}

function p2pkhScript(pubkeyHash: Uint8Array): Uint8Array {
  return concatBytes(new Uint8Array([0x76, 0xa9, 0x14]), pubkeyHash, new Uint8Array([0x88, 0xac]));
}

function p2shScript(scriptHash: Uint8Array): Uint8Array {
  return concatBytes(new Uint8Array([0xa9, 0x14]), scriptHash, new Uint8Array([0x87]));
}

function scriptForAddress(address: string): Uint8Array {
  const decoded = decodeCashAddr(address);
  return decoded.type === 'p2pkh' ? p2pkhScript(decoded.hash) : p2shScript(decoded.hash);
}

function le32(value: number): Uint8Array {
  return new Uint8Array([
    value & 0xff,
    (value >>> 8) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 24) & 0xff,
  ]);
}

function le64(value: bigint): Uint8Array {
  const out = new Uint8Array(8);
  let v = value;
  for (let i = 0; i < 8; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function varintBytes(value: number): Uint8Array {
  if (value < 0xfd) return new Uint8Array([value]);
  return new Uint8Array([0xfd, value & 0xff, (value >>> 8) & 0xff]);
}

/**
 * BIP-143 sighash preimage with FORKID, exactly as consensus defines it:
 * `version ‖ hashPrevouts ‖ hashSequence ‖ outpoint ‖ scriptCode ‖ value ‖
 * sequence ‖ hashOutputs ‖ locktime ‖ hashType(LE)`, double-SHA256d.
 */
export function computeBchSighash(args: {
  readonly tx: DecodedBchTx;
  readonly inputIndex: number;
  readonly scriptCode: Uint8Array;
  readonly value: bigint;
  readonly hashType?: number;
}): Uint8Array {
  const { tx, inputIndex, scriptCode, value } = args;
  const hashType = args.hashType ?? SIGHASH_FORKID_ALL;
  const input = tx.inputs[inputIndex];
  if (!input) {
    throw new EraSdkError('invalid-props', 'sighash input index out of range');
  }
  const hashPrevouts = sha256d(
    concatBytes(...tx.inputs.map((i) => concatBytes(i.txidLE, le32(i.index)))),
  );
  const hashSequence = sha256d(concatBytes(...tx.inputs.map((i) => le32(i.sequence))));
  const hashOutputs = sha256d(
    concatBytes(
      ...tx.outputs.map((o) => concatBytes(le64(o.value), varintBytes(o.script.length), o.script)),
    ),
  );
  const preimage = concatBytes(
    le32(tx.version),
    hashPrevouts,
    hashSequence,
    input.txidLE,
    le32(input.index),
    varintBytes(scriptCode.length),
    scriptCode,
    le64(value),
    le32(input.sequence),
    hashOutputs,
    le32(tx.locktime),
    le32(hashType),
  );
  return sha256d(preimage);
}

function toBigintValue(value: number | bigint, label: string): bigint {
  const v = typeof value === 'number' ? BigInt(value) : value;
  if (v <= 0n) throw new EraSdkError('invalid-props', `${label} must be positive`);
  return v;
}

function toPublicKeyBytes(publicKey: Uint8Array | string): Uint8Array {
  return typeof publicKey === 'string' ? hexToBytes(publicKey) : publicKey;
}

export function verifyBchSignedTx(args: VerifyBchSignedTxArgs): VerifyResult {
  try {
    const tx = decodeBchRawTx(args.rawTx);

    // Everything the verifier does not read is unchecked (the sighash is
    // recomputed FROM the decoded tx, so it is self-consistent with any
    // version/locktime/sequence). Pin the parameters the signer fixes.
    if (tx.version !== BCH_TX_VERSION || tx.locktime !== BCH_TX_LOCKTIME) {
      return failed(
        `transaction parameters (version ${tx.version}, locktime ${tx.locktime}) are not the device signer's (1, 0)`,
      );
    }
    for (let i = 0; i < tx.inputs.length; i++) {
      if (tx.inputs[i]!.sequence !== BCH_TX_SEQUENCE) {
        return failed(`input ${i} sequence is not the device signer's 0xfffffffd`);
      }
    }

    if (tx.inputs.length !== args.inputs.length) {
      return failed(
        `signed transaction has ${tx.inputs.length} inputs, the request had ${args.inputs.length}`,
      );
    }
    if (tx.outputs.length !== args.outputs.length) {
      return failed(
        `signed transaction has ${tx.outputs.length} outputs, the request had ${args.outputs.length}`,
      );
    }

    for (let i = 0; i < args.outputs.length; i++) {
      const requested = args.outputs[i]!;
      const actual = tx.outputs[i]!;
      if (actual.value !== toBigintValue(requested.value, `output ${i} value`)) {
        return failed(`output ${i} value differs from the request`);
      }
      if (!equalBytes(actual.script, scriptForAddress(requested.address))) {
        return failed(`output ${i} does not pay the requested address`);
      }
    }

    for (let i = 0; i < args.inputs.length; i++) {
      const requested = args.inputs[i]!;
      const actual = tx.inputs[i]!;
      const txidLE = hexToBytes(requested.txid).reverse();
      if (!equalBytes(actual.txidLE, txidLE) || actual.index !== requested.index) {
        return failed(`input ${i} spends a different outpoint than the request named`);
      }

      // scriptSig must be exactly push(sig‖0x41) push(pubkey33).
      const script = actual.scriptSig;
      if (script.length < 2) return failed(`input ${i} has no signature`);
      const sigLen = script[0]!;
      if (sigLen < 9 || 1 + sigLen + 1 > script.length) {
        return failed(`input ${i} scriptSig is not a signature push`);
      }
      const sigWithType = script.subarray(1, 1 + sigLen);
      const pubLen = script[1 + sigLen]!;
      if (pubLen !== 33 || 1 + sigLen + 1 + pubLen !== script.length) {
        return failed(`input ${i} scriptSig does not end with a compressed public key push`);
      }
      const pubkey = script.subarray(1 + sigLen + 1);
      if (!equalBytes(pubkey, toPublicKeyBytes(requested.publicKey))) {
        return failed(
          `input ${i} was signed with a different public key than the request named — ` +
            'the transaction cannot spend the requested UTXO',
        );
      }
      const hashType = sigWithType[sigWithType.length - 1]!;
      if (hashType !== SIGHASH_FORKID_ALL) {
        return failed(
          `input ${i} uses sighash 0x${hashType.toString(16)}, expected SIGHASH_ALL|FORKID (0x41)`,
        );
      }
      const sighash = computeBchSighash({
        tx,
        inputIndex: i,
        scriptCode: p2pkhScript(hash160(pubkey)),
        value: toBigintValue(requested.value, `input ${i} value`),
      });
      const signature = secp256k1.Signature.fromDER(
        sigWithType.subarray(0, sigWithType.length - 1),
      ).toCompactRawBytes();
      if (!secp256k1.verify(signature, sighash, pubkey)) {
        return failed(`input ${i} signature does not verify against the BIP-143 FORKID sighash`);
      }
    }

    if (args.txId !== undefined) {
      const computed = bytesToHex(sha256d(hexToBytes(args.rawTx)).reverse());
      if (computed !== args.txId.toLowerCase()) {
        return failed('reply txId does not match the hash of the signed transaction');
      }
    }
    return verified;
  } catch (e) {
    return failed(message(e));
  }
}

function message(e: unknown): string {
  return e instanceof EraSdkError || e instanceof Error ? e.message : String(e);
}
