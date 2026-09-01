import type { AnimatedUrOptions } from './qr/animated-ur';
import { AnimatedUr } from './qr/animated-ur';
import type { ChainContext } from './chains/shared';
import { toUr } from './chains/shared';
import type { Ur } from './ur/ur';
import { Ur as UrValue } from './ur/ur';

/**
 * Escape hatch for UR types this SDK has no dedicated module for (future
 * chains, custom registry items). You bring the CBOR; the SDK brings the UR
 * plumbing, fountain frames and the hardened scanner
 * (`EraConnect.scanner({expectedTypes})`).
 */
export class RawModule {
  constructor(private readonly context: ChainContext) {}

  /** Wrap raw CBOR bytes in a UR of the given registry type. */
  ur(type: string, cbor: Uint8Array): Ur {
    return new UrValue(type, cbor);
  }

  /** Parse a single-part `ur:` string into a Ur. */
  parse(text: string): Ur {
    return toUr(text);
  }

  /** Fragment + animate any UR. */
  animate(ur: Ur, options?: AnimatedUrOptions): AnimatedUr {
    return new AnimatedUr(ur, {
      maxFragmentLength: options?.maxFragmentLength ?? this.context.maxFragmentLength,
    });
  }
}
