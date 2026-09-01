import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha2';
import { keccak_256 } from '@noble/hashes/sha3';
import { createBase58check } from '@scure/base';
import { concatBytes, equalBytes, utf8Decode } from '../core/bytes';
import type { TronLatestBlock } from '../tron-proto/messages';
import type { SignedTronTx } from '../tron-proto/messages';
import { splitSignedTronTx } from '../tron-proto/messages';
import { firstBytes, firstVarint, readFields } from '../tron-proto/wire';
import type { VerifyResult } from './result';
import { failed, verified } from './result';

const base58check = createBase58check(sha256);

export interface VerifyTronSignatureArgs {
  /** The `raw_data` bytes the request carried. */
  readonly rawData: Uint8Array;
  /** The base58 owner address the transaction spends from. */
  readonly from: string;
  /** The reference block the request carried (enables the rebuild-path window check). */
  readonly latestBlock?: TronLatestBlock;
  /** The reply: either the split frame from `TronSignatureResult.signedTx`, or the raw hex. */
  readonly signedTx: SignedTronTx | string;
}

/**
 * The Tron reply is a fully signed transaction broadcast VERBATIM, so it is
 * checked on both counts: every signature must recover to the owner address,
 * and the transaction must move what the user approved.
 *
 * Byte equality with the request's `rawData` is the strong form. When the
 * bytes differ (a firmware that rebuilds `raw_data` from the semantic
 * fields), the fallback compares the fields that decide where the money goes,
 * plus the validity window against the reference block.
 */
export function verifyTronSignature(args: VerifyTronSignatureArgs): VerifyResult {
  let signedTx: SignedTronTx;
  try {
    signedTx = typeof args.signedTx === 'string' ? splitSignedTronTx(args.signedTx) : args.signedTx;
  } catch (e) {
    return failed(`the returned Tron transaction is not readable: ${(e as Error).message}`);
  }
  if (signedTx.signatures.length === 0) {
    return failed('the returned Tron transaction carries no signature');
  }
  if (!args.from) {
    return failed('no owner address to check the signature against');
  }

  const digest = sha256(signedTx.rawData);
  for (const signature of signedTx.signatures) {
    const recovered = recoverTronAddress(digest, signature);
    if (recovered === null) return failed('signature could not be checked');
    if (recovered !== args.from) {
      return failed('the signature does not belong to this account');
    }
  }

  if (equalBytes(signedTx.rawData, args.rawData)) return verified;

  // Rebuild path: the firmware built its own raw_data from the semantic
  // fields. Compare the operation, then the validity window.
  const contractResult = compareContracts(args.rawData, signedTx.rawData);
  if (contractResult !== null) return contractResult;
  if (args.latestBlock === undefined) {
    return failed(
      'the returned raw_data differs from the request and no latestBlock was provided to check the validity window',
    );
  }
  return compareWindow(signedTx.rawData, args.latestBlock);
}

function recoverTronAddress(digest: Uint8Array, signature: Uint8Array): string | null {
  if (signature.length < 65) return null;
  const recovery = signature[64]!;
  const recoveryId = recovery >= 27 ? (recovery - 27) & 1 : recovery & 1;
  try {
    const point = secp256k1.Signature.fromCompact(signature.slice(0, 64))
      .addRecoveryBit(recoveryId)
      .recoverPublicKey(digest);
    const hash = keccak_256(point.toRawBytes(false).slice(1));
    return base58check.encode(concatBytes(new Uint8Array([0x41]), hash.slice(12)));
  } catch {
    return null;
  }
}

// --- raw_data structural comparison ---------------------------------------

interface TronContract {
  readonly typeUrl: string;
  readonly type: bigint;
  readonly parameter: Uint8Array;
}

interface TronRawData {
  readonly contracts: readonly TronContract[];
  readonly expiration: bigint;
  readonly timestamp: bigint;
}

function parseRawData(bytes: Uint8Array): TronRawData | null {
  try {
    const fields = readFields(bytes);
    const contracts: TronContract[] = [];
    for (const f of fields) {
      if (f.field === 11 && f.wireType === 2) {
        const c = readFields(f.bytes);
        const anyBytes = firstBytes(c, 2);
        const any = anyBytes ? readFields(anyBytes) : [];
        const typeUrlBytes = anyBytes ? firstBytes(any, 1) : null;
        contracts.push({
          typeUrl: typeUrlBytes ? utf8Decode(typeUrlBytes) : '',
          type: firstVarint(c, 1) ?? 0n,
          parameter: (anyBytes && firstBytes(any, 2)) || new Uint8Array(0),
        });
      }
    }
    return {
      contracts,
      expiration: firstVarint(fields, 8) ?? 0n,
      timestamp: firstVarint(fields, 14) ?? 0n,
    };
  } catch {
    return null;
  }
}

/** null = contracts match (continue to the window check); a result = verdict. */
function compareContracts(askedBytes: Uint8Array, repliedBytes: Uint8Array): VerifyResult | null {
  const asked = parseRawData(askedBytes);
  const replied = parseRawData(repliedBytes);
  if (!asked) return failed('the Tron transaction built by the app could not be read');
  if (!replied) return failed('the Tron transaction built by the device could not be read');
  if (asked.contracts.length !== 1 || replied.contracts.length !== 1) {
    return failed('the Tron transaction does not carry exactly one contract');
  }
  const a = asked.contracts[0]!;
  const b = replied.contracts[0]!;
  const kindA = contractKind(a);
  const kindB = contractKind(b);
  if (kindA !== kindB) {
    return failed('the returned Tron transaction is a different kind of operation');
  }

  const pa = readFieldsSafe(a.parameter);
  const pb = readFieldsSafe(b.parameter);
  if (!pa || !pb) return failed('the Tron contract parameters could not be read');

  switch (kindA) {
    case 'transfer':
      // TransferContract {1: owner, 2: to, 3: amount}
      if (
        sameBytesField(pa, pb, 1) &&
        sameBytesField(pa, pb, 2) &&
        (firstVarint(pa, 3) ?? 0n) === (firstVarint(pb, 3) ?? 0n)
      ) {
        return null;
      }
      break;
    case 'transferAsset':
      // TransferAssetContract {1: asset, 2: owner, 3: to, 4: amount}
      if (
        sameBytesField(pa, pb, 1) &&
        sameBytesField(pa, pb, 2) &&
        sameBytesField(pa, pb, 3) &&
        (firstVarint(pa, 4) ?? 0n) === (firstVarint(pb, 4) ?? 0n)
      ) {
        return null;
      }
      break;
    case 'triggerSmartContract':
      // TriggerSmartContract {1: owner, 2: contract, 3: call_value, 4: data}.
      // call_value: zero and absent are the same thing — the two sides are
      // serialized by different protobuf writers that disagree on whether a
      // zero scalar is written, and every TRC-20 transfer carries call_value 0.
      if (
        sameBytesField(pa, pb, 1) &&
        sameBytesField(pa, pb, 2) &&
        (firstVarint(pa, 3) ?? 0n) === (firstVarint(pb, 3) ?? 0n) &&
        sameBytesField(pa, pb, 4)
      ) {
        return null;
      }
      break;
    default:
      // An operation this gate cannot compare field by field is not waved
      // through: without byte equality there is nothing left to bind it to
      // what the user approved.
      return failed('the returned Tron transaction carries an operation this check cannot compare');
  }
  return failed('the returned Tron transaction does not match the one approved');
}

type ContractKind = 'transfer' | 'transferAsset' | 'triggerSmartContract' | 'other';

function contractKind(contract: TronContract): ContractKind {
  if (contract.typeUrl.endsWith('.TransferContract') || contract.type === 1n) return 'transfer';
  if (contract.typeUrl.endsWith('.TransferAssetContract') || contract.type === 2n) {
    return 'transferAsset';
  }
  if (contract.typeUrl.endsWith('.TriggerSmartContract') || contract.type === 31n) {
    return 'triggerSmartContract';
  }
  return 'other';
}

function readFieldsSafe(bytes: Uint8Array): ReturnType<typeof readFields> | null {
  try {
    return readFields(bytes);
  } catch {
    return null;
  }
}

function sameBytesField(
  a: ReturnType<typeof readFields>,
  b: ReturnType<typeof readFields>,
  field: number,
): boolean {
  const x = firstBytes(a, field) ?? new Uint8Array(0);
  const y = firstBytes(b, field) ?? new Uint8Array(0);
  return equalBytes(x, y);
}

/**
 * Firmware formulas, not policy: the two device-side transaction builders
 * stamp `timestamp` with the request's reference-block timestamp verbatim and
 * set `expiration` to +10 minutes (one builder) or +10 hours (the other). A
 * range spanning both cannot refuse a reply the live fleet produces.
 */
const MIN_EXPIRY_MS = 10n * 60n * 1000n;
const MAX_EXPIRY_MS = 10n * 60n * 60n * 1000n;

function compareWindow(repliedBytes: Uint8Array, latestBlock: TronLatestBlock): VerifyResult {
  const replied = parseRawData(repliedBytes);
  if (!replied) return failed('the Tron transaction built by the device could not be read');
  const block = BigInt(latestBlock.timestamp);
  if (replied.timestamp !== block) {
    return failed(
      'the returned Tron transaction is stamped against a different reference block than the one we sent',
    );
  }
  const validFor = replied.expiration - block;
  if (validFor < MIN_EXPIRY_MS || validFor > MAX_EXPIRY_MS) {
    return failed(
      `the returned Tron transaction is valid for ${validFor} ms after the reference block, outside the firmware's ${MIN_EXPIRY_MS}-${MAX_EXPIRY_MS} ms window`,
    );
  }
  return verified;
}
