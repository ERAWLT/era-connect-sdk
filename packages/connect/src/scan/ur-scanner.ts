import type { EraErrorCode } from '../core/errors';
import { EraSdkError } from '../core/errors';
import { UrDecoder } from '../ur/decoder';
import type { Ur } from '../ur/ur';
import { urTypeOf } from '../ur/ur';

export interface UrScannerOptions {
  /**
   * Pin: frames of any other UR type are rejected BEFORE the fountain decoder
   * sees them. The decoder commits to a stream once one binds, so a frame that
   * gets that far has a say in what the rest of the session may look like —
   * pinning is the cheap half of the hostile-QR cure (the decoder's
   * two-fragment binding rule is the other half).
   */
  readonly expectedTypes?: readonly string[];
}

export interface ScanRejection {
  readonly code: EraErrorCode;
  readonly message: string;
  /**
   * Consecutive occurrences of this same rejection. A static hostile or
   * malformed QR produces the identical rejection at camera framerate; this
   * counter lets a UI or a log show it once instead of ~10 times per second.
   */
  readonly repeated: number;
}

export type ScanFeedResult =
  | {
      readonly kind: 'progress';
      readonly progress: number;
      readonly framesReceived: number;
      readonly framesExpected: number;
    }
  | { readonly kind: 'duplicate' }
  | { readonly kind: 'rejected'; readonly rejection: ScanRejection }
  | { readonly kind: 'complete'; readonly ur: Ur };

/**
 * Accumulates camera frames into a UR. Synchronous and non-throwing on the
 * feed path (safe to call from camera callbacks); malformed frames come back
 * as typed rejections, never exceptions.
 */
export class UrScanner {
  private readonly decoder = new UrDecoder();
  private readonly expectedTypes: ReadonlySet<string> | null;
  private readonly seen = new Set<string>();
  private rejection: ScanRejection | null = null;

  /** Distinct frames remembered for dedup. Attacker-suppliable strings, so capped. */
  private static readonly maxRememberedFrames = 4096;

  constructor(options?: UrScannerOptions) {
    this.expectedTypes = options?.expectedTypes ? new Set(options.expectedTypes) : null;
  }

  get isComplete(): boolean {
    return this.decoder.isComplete;
  }

  get progress(): number {
    return this.decoder.progress;
  }

  /** The UR type of the bound stream, or null until one binds. */
  get urType(): string | null {
    return this.decoder.type === '' ? null : this.decoder.type;
  }

  get framesReceived(): number {
    return this.decoder.partsReceived;
  }

  get framesExpected(): number {
    return this.decoder.partsExpected;
  }

  get lastRejection(): ScanRejection | null {
    return this.rejection;
  }

  /** Feed one scanned frame. */
  receivePart(frame: string): ScanFeedResult {
    if (this.decoder.isComplete) {
      return { kind: 'complete', ur: this.decoder.result() };
    }
    if (this.seen.has(frame)) return { kind: 'duplicate' };

    // Type pin BEFORE any decoding work.
    const type = urTypeOf(frame);
    if (type === null) {
      return this.reject('not-a-ur', 'not a UR frame');
    }
    if (this.expectedTypes && !this.expectedTypes.has(type)) {
      // The type is attacker-sized (the grammar allows an unbounded letter
      // run) — truncate before it reaches a message or a log.
      const shown = type.length > 32 ? `${type.slice(0, 32)}…` : type;
      return this.reject(
        'wrong-ur-type',
        `ignored a "${shown}" frame; expected ${[...this.expectedTypes].join(' or ')}`,
      );
    }

    // Remembered only now: junk that never reached the decoder must not be
    // able to fill the dedup budget.
    if (this.seen.size < UrScanner.maxRememberedFrames) this.seen.add(frame);

    let complete: boolean;
    try {
      complete = this.decoder.receivePart(frame);
    } catch (e) {
      // Only the code, never the frame contents — attacker-sized, and on the
      // linking path a wallet's own bytes.
      const code = e instanceof EraSdkError ? e.code : 'not-a-ur';
      return this.reject(code, 'unreadable UR frame');
    }
    if (this.decoder.lastRefusal) {
      return this.reject(this.decoder.lastRefusal.code, this.decoder.lastRefusal.message);
    }
    if (complete) {
      this.rejection = null;
      return { kind: 'complete', ur: this.decoder.result() };
    }
    return {
      kind: 'progress',
      progress: this.decoder.progress,
      framesReceived: this.decoder.partsReceived,
      framesExpected: this.decoder.partsExpected,
    };
  }

  /** The assembled UR. Throws `incomplete-scan` until done. */
  result(): Ur {
    return this.decoder.result();
  }

  private reject(code: EraErrorCode, message: string): ScanFeedResult {
    const previous = this.rejection;
    this.rejection =
      previous && previous.code === code && previous.message === message
        ? { code, message, repeated: previous.repeated + 1 }
        : { code, message, repeated: 1 };
    return { kind: 'rejected', rejection: this.rejection };
  }
}

/** A scanner whose completed UR parses into a typed result (a chain signature). */
export class TypedUrScanner<TResult> extends UrScanner {
  constructor(
    options: UrScannerOptions,
    private readonly parseResult: (ur: Ur) => TResult,
  ) {
    super(options);
  }

  /** Assemble + parse + validate (UR type, request-id echo) in one call. */
  parse(): TResult {
    return this.parseResult(this.result());
  }
}
