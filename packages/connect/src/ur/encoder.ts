import { EraSdkError } from '../core/errors';
import { bytewordsEncode } from './bytewords';
import { crc32 } from './crc32';
import { fragmentCbor } from './fragment';
import { chooseFragmentIndexes } from './sampler';
import type { Ur } from './ur';

/**
 * BC-UR fountain encoder.
 *
 * Partitioning picks the LARGEST fragment length `<= maxFragmentLength` that
 * evenly covers the payload (`ceil(len/count)` for the smallest sufficient
 * `count`), and the last fragment is zero-padded to the common length — both
 * exactly as the reference encoders do, because the receiving side's header
 * consistency check assumes this relation.
 *
 * A payload that fits one fragment is emitted as the plain single-part
 * `ur:<type>/<body>` form on every call — never as a `1-1` sequence.
 */
export class UrFountainEncoder {
  readonly ur: Ur;
  private readonly fragments: Uint8Array[];
  private readonly checksum: number;
  private seqNum = 0;

  constructor(ur: Ur, maxFragmentLength = 180, minFragmentLength = 10) {
    if (ur.cbor.length === 0) {
      throw new EraSdkError('invalid-props', 'cannot encode an empty UR payload');
    }
    if (maxFragmentLength < minFragmentLength || maxFragmentLength <= 0 || minFragmentLength <= 0) {
      throw new EraSdkError('invalid-props', 'invalid fragment length bounds');
    }
    this.ur = ur;
    this.checksum = crc32(ur.cbor);
    this.fragments = partition(ur.cbor, maxFragmentLength, minFragmentLength);
  }

  get isSinglePart(): boolean {
    return this.fragments.length <= 1;
  }

  /** How many source fragments the payload was split into (1 for single-part). */
  get fragmentCount(): number {
    return this.fragments.length;
  }

  /** Next wire frame, uppercase. Single-part payloads return the same string every call. */
  nextPart(): string {
    if (this.isSinglePart) return this.ur.toWireString();

    this.seqNum += 1;
    const indexes = chooseFragmentIndexes(this.seqNum, this.fragments.length, this.checksum);
    const first = this.fragments[0]!;
    const mixed = new Uint8Array(first.length);
    for (const index of indexes) {
      const fragment = this.fragments[index]!;
      for (let i = 0; i < mixed.length; i++) mixed[i] = mixed[i]! ^ (fragment[i] ?? 0);
    }
    const body = fragmentCbor(
      this.seqNum,
      this.fragments.length,
      this.ur.cbor.length,
      this.checksum,
      mixed,
    );
    return `ur:${this.ur.type}/${this.seqNum}-${this.fragments.length}/${bytewordsEncode(body)}`.toUpperCase();
  }
}

/** Largest `ceil(len/count) <= maxLength` split, last fragment zero-padded. */
function partition(payload: Uint8Array, maxLength: number, minLength: number): Uint8Array[] {
  const maxCount = Math.ceil(payload.length / minLength);
  let fragmentLength = payload.length;
  for (let count = 1; count <= maxCount; count++) {
    fragmentLength = Math.ceil(payload.length / count);
    if (fragmentLength <= maxLength) break;
  }
  const fragments: Uint8Array[] = [];
  for (let offset = 0; offset < payload.length; offset += fragmentLength) {
    const slice = payload.slice(offset, offset + fragmentLength);
    if (slice.length < fragmentLength) {
      const padded = new Uint8Array(fragmentLength);
      padded.set(slice);
      fragments.push(padded);
    } else {
      fragments.push(slice);
    }
  }
  return fragments;
}
