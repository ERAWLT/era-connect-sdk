import { cborDecode } from '../cbor/decode';
import { cborEncode } from '../cbor/encode';
import { cbArray, cbBytes, cbUint } from '../cbor/model';
import { headerIsConsistent, UrLimits } from './limits';
import { chooseFragmentIndexes } from './sampler';

/** A validated multi-part UR fragment. */
export interface Fragment {
  readonly type: string;
  readonly seqNum: number;
  readonly seqLength: number;
  readonly messageLength: number;
  readonly checksum: number;
  readonly part: Uint8Array;
  readonly indexes: readonly number[];
}

export const isSimple = (fragment: Fragment): boolean => fragment.indexes.length === 1;

/** Fragment CBOR: the definite 5-array `[seqNum, seqLen, msgLen, checksum, bytes]`. */
export function fragmentCbor(
  seqNum: number,
  seqLength: number,
  messageLength: number,
  checksum: number,
  part: Uint8Array,
): Uint8Array {
  return cborEncode(
    cbArray([
      cbUint(seqNum),
      cbUint(seqLength),
      cbUint(messageLength),
      cbUint(checksum),
      cbBytes(part),
    ]),
  );
}

/**
 * Parse and validate a fragment payload, or return null.
 *
 * Every field here is chosen by whoever printed the QR, and three of them size
 * allocations or loops downstream — so the bounds are checked as a set BEFORE
 * the (quadratic) fountain index derivation pays for anything.
 */
export function tryParseFragment(type: string, payload: Uint8Array): Fragment | null {
  let decoded: ReturnType<typeof cborDecode>;
  try {
    decoded = cborDecode(payload);
  } catch {
    return null;
  }
  if (decoded.kind !== 'array' || decoded.items.length !== 5) return null;

  const seqNum = uintInRange(decoded.items[0]);
  const seqLength = uintInRange(decoded.items[1]);
  const messageLength = uintInRange(decoded.items[2]);
  const checksum = uintInRange(decoded.items[3]);
  const partValue = decoded.items[4];
  if (
    seqNum === null ||
    seqLength === null ||
    messageLength === null ||
    checksum === null ||
    partValue?.kind !== 'bytes'
  ) {
    return null;
  }
  const part = partValue.value;
  if (
    !headerIsConsistent({ seqNum, seqLength, messageLength, checksum, fragmentLength: part.length })
  ) {
    return null;
  }
  return {
    type,
    seqNum,
    seqLength,
    messageLength,
    checksum,
    part,
    indexes: chooseFragmentIndexes(seqNum, seqLength, checksum),
  };
}

/** A CBOR uint in [0, 2^32), or null for anything else. */
function uintInRange(value: { kind: string } | undefined): number | null {
  if (value?.kind !== 'uint') return null;
  const big = (value as { kind: 'uint'; value: bigint }).value;
  if (big < 0n || big > BigInt(UrLimits.maxUint32)) return null;
  return Number(big);
}
