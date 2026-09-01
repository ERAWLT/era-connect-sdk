import type { EraErrorCode } from '../core/errors';
import { EraSdkError } from '../core/errors';
import { crc32 } from './crc32';
import type { Fragment } from './fragment';
import { isSimple, tryParseFragment } from './fragment';
import { UrLimits } from './limits';
import { parseUrString, Ur } from './ur';

/** Why the last frame was turned away by validation (null = used or buffered). */
export interface UrRefusal {
  readonly code: EraErrorCode;
  readonly message: string;
}

/**
 * BC-UR fountain decoder with hostile-input stream binding.
 *
 * The naive decoder pins its expectations to the FIRST fragment it ever sees
 * and drops everything that disagrees. That is right while the only thing in
 * front of the camera is the device — and it is exactly how one hostile QR (a
 * sticker, a poster, a second screen) used to end the whole session: it bound
 * first, and the device's real answer could never assemble.
 *
 * The cure is to make binding harder, not reversible:
 *
 *  - a stream binds only PROVISIONALLY on its first fragment, and is
 *    CONFIRMED only when a second, distinct fragment of the same stream
 *    arrives (same fingerprint, different seqNum). A static QR is one
 *    fragment forever and can never confirm itself;
 *  - a provisional binding is dropped after 32 non-matching frames — a
 *    genuine stream confirms on its very next frame, so this cannot be aimed
 *    at one;
 *  - a CONFIRMED binding is never evicted. Any recovery path is an eviction
 *    path, so there is none. A rogue fragment that poisons the XOR costs the
 *    accumulated progress (rescan one animation pass), never the binding;
 *  - a single-part UR cannot complete the scan while a confirmed multi-part
 *    assembly holds received fragments.
 *
 * What this does not defend against is an attacker who owns the camera
 * outright — if the only well-formed UR in view is theirs, it assembles. The
 * layers above (type pinning per request, request-id echo, verification
 * helpers) are what refuse that.
 */
export class UrDecoder {
  private boundType = '';
  private seqLength = 0;
  private expectedMessageLength = 0;
  private expectedChecksum = 0;
  private expectedFragmentLength = 0;
  private confirmed = false;
  private framesSinceBinding = 0;
  private bindingSeqNum = 0;

  private readonly expectedIndexes: number[] = [];
  private readonly receivedIndexes: number[] = [];
  private mixedParts: Fragment[] = [];
  private readonly queuedParts: Fragment[] = [];
  private readonly simpleParts: Fragment[] = [];

  private payload: Uint8Array | null = null;
  private completedType = '';

  /** How long a provisional binding may stand without a second fragment of its own. */
  private static readonly framesBeforeDroppingProvisional = 32;

  lastRefusal: UrRefusal | null = null;

  get isComplete(): boolean {
    return this.payload !== null;
  }

  /** The type of the bound (or completed) stream; empty until one binds. */
  get type(): string {
    return this.payload !== null ? this.completedType : this.boundType;
  }

  get partsExpected(): number {
    return this.expectedIndexes.length;
  }

  get partsReceived(): number {
    return this.receivedIndexes.length;
  }

  /** Assembly progress in [0, 1]. */
  get progress(): number {
    if (this.isComplete) return 1;
    if (this.expectedIndexes.length === 0) return 0;
    return this.receivedIndexes.length / this.expectedIndexes.length;
  }

  /** The assembled UR. Throws until `isComplete`. */
  result(): Ur {
    if (this.payload === null) {
      throw new EraSdkError('incomplete-scan', 'UR not fully assembled yet');
    }
    return new Ur(this.completedType, this.payload);
  }

  /**
   * Feed one scanned frame. Returns true once the UR is fully assembled.
   *
   * Throws EraSdkError for frames that are not parseable URs at all
   * (`not-a-ur`, `malformed-bytewords`, `checksum-mismatch`,
   * `malformed-sequence`); refusals of parseable frames set [lastRefusal]
   * and return false.
   */
  receivePart(text: string): boolean {
    if (this.isComplete) return false;
    this.lastRefusal = null;

    const parsed = parseUrString(text);

    if (parsed.seq === null) {
      // Single-part branch. It never reaches the fragment-header bounds, so
      // the ceiling is enforced here too — otherwise this is the one shape
      // that can hand an unbounded payload to the layers above.
      if (parsed.payload.length === 0 || parsed.payload.length > UrLimits.maxMessageBytes) {
        this.lastRefusal = {
          code: 'limit-exceeded',
          message: `single-part payload of ${parsed.payload.length} bytes is outside 1..${UrLimits.maxMessageBytes}`,
        };
        return false;
      }
      // A single-part frame must not walk over an assembly under way: every
      // genuine device reply is single-part, so the veto is deliberately
      // narrow — only a CONFIRMED multi-part stream with collected fragments.
      if (this.confirmed && this.receivedIndexes.length > 0) {
        this.lastRefusal = {
          code: 'fragment-mismatch',
          message: `a single-part UR arrived while a "${this.boundType}" assembly was under way`,
        };
        return false;
      }
      this.completedType = parsed.type;
      this.payload = parsed.payload;
      return true;
    }

    // Validated BEFORE construction: index derivation is quadratic in the
    // header's seqLength, so an unchecked header has already cost whatever
    // the attacker asked for by the time anyone could reject it.
    const fragment = tryParseFragment(parsed.type, parsed.payload);
    if (fragment === null) {
      this.lastRefusal = {
        code: 'limit-exceeded',
        message: 'fragment header is malformed or outside the UrLimits bounds',
      };
      return false;
    }
    if (fragment.seqNum !== parsed.seq.num || fragment.seqLength !== parsed.seq.length) {
      this.lastRefusal = {
        code: 'fragment-mismatch',
        message: 'fragment header disagrees with the ur: path sequence',
      };
      return false;
    }
    if (!this.checkBinding(fragment)) return false;

    this.queuedParts.push(fragment);
    while (!this.isComplete && this.queuedParts.length > 0) {
      this.processQueuedItem();
    }
    return this.isComplete;
  }

  private fingerprintOf(
    type: string,
    seqLength: number,
    messageLength: number,
    checksum: number,
    fragmentLength: number,
  ): string {
    return `${type}|${seqLength}|${messageLength}|${checksum}|${fragmentLength}`;
  }

  /** Decide whether the fragment belongs to the bound stream; bind/confirm/drop per the rules above. */
  private checkBinding(fragment: Fragment): boolean {
    const fingerprint = this.fingerprintOf(
      fragment.type,
      fragment.seqLength,
      fragment.messageLength,
      fragment.checksum,
      fragment.part.length,
    );

    if (this.boundType !== '') {
      const bound = this.fingerprintOf(
        this.boundType,
        this.seqLength,
        this.expectedMessageLength,
        this.expectedChecksum,
        this.expectedFragmentLength,
      );
      if (fingerprint === bound) {
        // A second DISTINCT fragment is the proof; the same frame held in
        // front of the camera cannot confirm itself.
        if (!this.confirmed && fragment.seqNum !== this.bindingSeqNum) this.confirmed = true;
        return true;
      }
      if (this.confirmed) {
        this.lastRefusal = {
          code: 'fragment-mismatch',
          message: 'fragment belongs to a different stream than the confirmed assembly',
        };
        return false;
      }
      this.framesSinceBinding += 1;
      if (this.framesSinceBinding < UrDecoder.framesBeforeDroppingProvisional) {
        this.lastRefusal = {
          code: 'fragment-mismatch',
          message: 'fragment belongs to a different stream than the provisional binding',
        };
        return false;
      }
      this.discardBinding();
    }

    this.boundType = fragment.type;
    this.seqLength = fragment.seqLength;
    this.expectedMessageLength = fragment.messageLength;
    this.expectedChecksum = fragment.checksum;
    this.expectedFragmentLength = fragment.part.length;
    this.bindingSeqNum = fragment.seqNum;
    this.confirmed = false;
    this.framesSinceBinding = 0;

    this.expectedIndexes.length = 0;
    for (let i = 0; i < fragment.seqLength; i++) this.expectedIndexes.push(i);
    return true;
  }

  /** Drop a binding that never proved itself (provisional only). */
  private discardBinding(): void {
    this.boundType = '';
    this.seqLength = 0;
    this.expectedMessageLength = 0;
    this.expectedChecksum = 0;
    this.expectedFragmentLength = 0;
    this.confirmed = false;
    this.framesSinceBinding = 0;
    this.bindingSeqNum = 0;
    this.expectedIndexes.length = 0;
    this.receivedIndexes.length = 0;
    this.mixedParts = [];
    this.queuedParts.length = 0;
    this.simpleParts.length = 0;
  }

  /**
   * Throw away the accumulation, KEEPING the binding.
   *
   * Reached when the reassembled payload does not hash to the stream's own
   * declared checksum — a rogue fragment that copied the visible header and
   * poisoned the XOR. Unbinding here would hand back the eviction primitive
   * the binding rule denies, so only the collected fragments are discarded:
   * one pass of the animation for the genuine sender, one fragment per pass
   * for the attacker, forever.
   */
  private discardAccumulation(): void {
    this.expectedIndexes.length = 0;
    if (this.seqLength > 0) {
      for (let i = 0; i < this.seqLength; i++) this.expectedIndexes.push(i);
    }
    this.receivedIndexes.length = 0;
    this.mixedParts = [];
    this.queuedParts.length = 0;
    this.simpleParts.length = 0;
  }

  private processQueuedItem(): void {
    const part = this.queuedParts.shift();
    if (!part) return;
    if (isSimple(part)) {
      this.processSimplePart(part);
    } else {
      this.processMixedPart(part);
    }
  }

  private processSimplePart(fragment: Fragment): void {
    const fragmentIndex = fragment.indexes[0]!;
    if (this.receivedIndexes.includes(fragmentIndex)) return;

    this.simpleParts.push(fragment);
    this.receivedIndexes.push(fragmentIndex);

    if (sameMembers(this.receivedIndexes, this.expectedIndexes)) {
      const sorted = [...this.simpleParts].sort((a, b) => a.indexes[0]! - b.indexes[0]!);
      let joinedLength = 0;
      for (const p of sorted) joinedLength += p.part.length;
      const joined = new Uint8Array(joinedLength);
      let offset = 0;
      for (const p of sorted) {
        joined.set(p.part, offset);
        offset += p.part.length;
      }
      if (joined.length < this.expectedMessageLength) {
        this.discardAccumulation();
        return;
      }
      const candidate = joined.slice(0, this.expectedMessageLength);
      // Between fragments the checksum only proves they agree with each
      // other; against the assembled message it proves the message is the one
      // the stream was describing. This is the single check that catches a
      // rogue fragment XOR'd into a genuine stream.
      if (crc32(candidate) !== this.expectedChecksum) {
        this.discardAccumulation();
        return;
      }
      this.completedType = this.boundType;
      this.payload = candidate;
    } else {
      this.reduceMixedBy(fragment);
    }
  }

  private processMixedPart(fragment: Fragment): void {
    if (this.mixedParts.some((e) => sameMembers([...e.indexes], [...fragment.indexes]))) return;
    // Distinct mixed parts are attacker-suppliable one per frame and each is
    // compared against every other on the next reduction. A real stream never
    // holds more mixed parts than it has source fragments. Backstop only —
    // the reduction's collapse rate keeps real lists tiny.
    if (this.mixedParts.length >= UrLimits.maxFragmentCount) return;

    let simple = fragment;
    for (const s of this.simpleParts) simple = this.reducePartByPart(simple, s);

    let part = simple;
    for (const m of this.mixedParts) part = this.reducePartByPart(part, m);

    if (isSimple(part)) {
      this.queuedParts.push(part);
    } else {
      this.reduceMixedBy(part);
      this.mixedParts.push(part);
    }
  }

  private reduceMixedBy(fragment: Fragment): void {
    const newMixed: Fragment[] = [];
    for (const item of this.mixedParts) {
      const reduced = this.reducePartByPart(item, fragment);
      if (isSimple(reduced)) {
        this.queuedParts.push(item);
      } else {
        newMixed.push(reduced);
      }
    }
    this.mixedParts = newMixed;
  }

  private reducePartByPart(a: Fragment, b: Fragment): Fragment {
    if (!b.indexes.every((e) => a.indexes.includes(e))) return a;

    const newIndexes = a.indexes.filter((e) => !b.indexes.includes(e));
    const newLength = Math.max(a.part.length, b.part.length);
    const newPart = new Uint8Array(newLength);
    for (let i = 0; i < newLength; i++) {
      newPart[i] = (a.part[i] ?? 0) ^ (b.part[i] ?? 0);
    }
    return {
      type: a.type,
      seqNum: a.seqNum,
      seqLength: a.seqLength,
      messageLength: this.expectedMessageLength,
      checksum: crc32(a.part),
      part: newPart,
      indexes: newIndexes,
    };
  }
}

/** Order-insensitive membership equality (mirrors the reference `arraysEqual`). */
function sameMembers(a: readonly number[], b: readonly number[]): boolean {
  if (a.length !== b.length) return false;
  return a.every((e) => b.includes(e));
}
