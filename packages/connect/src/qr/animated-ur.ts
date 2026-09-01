import { UrFountainEncoder } from '../ur/encoder';
import type { Ur } from '../ur/ur';

export interface AnimatedUrOptions {
  /**
   * Payload bytes per fountain fragment. The on-wire frame adds a ~16-byte
   * CBOR header, so the default 180 keeps frames within the ~200-byte
   * per-fragment ceiling hardware-wallet cameras scan reliably. Larger
   * fragments mean fewer frames but denser QR codes.
   */
  readonly maxFragmentLength?: number;
}

export const DEFAULT_FRAGMENT_LENGTH = 180;

/**
 * Frame source for rendering a UR as an animated QR.
 *
 * Drive `nextFrame()` from your own ticker (~8 fps is the battle-tested
 * default) and hand each string to your QR component. Frames are UPPERCASE so
 * the QR encoder can use alphanumeric mode (~45% denser than byte mode).
 */
export class AnimatedUr {
  private readonly encoder: UrFountainEncoder;

  constructor(ur: Ur, options?: AnimatedUrOptions) {
    this.encoder = new UrFountainEncoder(ur, options?.maxFragmentLength ?? DEFAULT_FRAGMENT_LENGTH);
  }

  /** Whether the payload fits one QR (no animation needed). */
  get isSingleFrame(): boolean {
    return this.encoder.isSinglePart;
  }

  /** The UR registry type being sent, e.g. `eth-sign-request`. */
  get urType(): string {
    return this.encoder.ur.type;
  }

  /** How many source fragments the payload was split into. */
  get fragmentCount(): number {
    return this.encoder.fragmentCount;
  }

  /** Next wire frame (uppercase). Single-frame payloads return the same string every call. */
  nextFrame(): string {
    return this.encoder.nextPart();
  }

  /** The whole request as ONE lowercase `ur:` string — the loggable form, not what is on screen. */
  toString(): string {
    return this.encoder.ur.toString();
  }
}
