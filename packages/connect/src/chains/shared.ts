import { cborDecode } from '../cbor/decode';
import type { CborValue } from '../cbor/model';
import { asMap, mapGet, stripTags } from '../cbor/model';
import { equalBytes } from '../core/bytes';
import { EraSdkError } from '../core/errors';
import type { RandomBytesFn } from '../core/rand';
import { normalizeRequestId, randomRequestId } from '../core/rand';
import type { AnimatedUrOptions } from '../qr/animated-ur';
import { AnimatedUr, DEFAULT_FRAGMENT_LENGTH } from '../qr/animated-ur';
import { TypedUrScanner } from '../scan/ur-scanner';
import type { Ur } from '../ur/ur';
import { parseUrString, Ur as UrValue } from '../ur/ur';

/** Resolved SDK configuration handed to every chain module. */
export interface ChainContext {
  readonly origin: string;
  readonly randomBytes: RandomBytesFn | undefined;
  readonly maxFragmentLength: number;
}

/** SDK configuration. Everything is optional; the SDK performs NO network I/O ever. */
export interface EraConnectConfig {
  /**
   * Wallet name the device shows the user on every request ("Sign for
   * <origin>?"). Set it once here; individual requests can override.
   */
  readonly origin?: string | undefined;
  /**
   * CSPRNG override. By default `globalThis.crypto.getRandomValues` is used;
   * on React Native install `react-native-get-random-values`, or inject a
   * secure source here. Request-id minting throws `no-secure-random` when
   * neither is available.
   */
  readonly randomBytes?: RandomBytesFn | undefined;
  /** Default payload bytes per animated-QR fragment (180 unless overridden). */
  readonly maxFragmentLength?: number | undefined;
}

export const DEFAULT_ORIGIN = 'ERA Connect';

export function resolveContext(config?: EraConnectConfig | ChainContext): ChainContext {
  return {
    origin: config?.origin ?? DEFAULT_ORIGIN,
    randomBytes: config?.randomBytes ?? undefined,
    maxFragmentLength: config?.maxFragmentLength ?? DEFAULT_FRAGMENT_LENGTH,
  };
}

/** Optional expectations when parsing a reply standalone (outside `SignRequest.scanner()`). */
export interface ExpectedReply {
  readonly requestId?: Uint8Array | string;
}

/**
 * A built sign request: the UR to display plus everything needed to consume
 * the reply. The request id is minted at CONSTRUCTION so the same object that
 * renders the QR also validates the echo — a reply carrying a different id
 * (from an earlier, cancelled flow re-presented to the camera) is refused
 * instead of accepted.
 */
export interface SignRequest<TResult> {
  readonly ur: Ur;
  /** Absent only where the protocol has no request id (Bitcoin PSBT). */
  readonly requestId: Uint8Array | undefined;
  /** UR types that can answer THIS request. */
  readonly replyTypes: readonly string[];
  /** Non-fatal advisories (e.g. `blind-sign-threshold`). */
  readonly warnings: readonly string[];
  /** Fragment + animate for display. */
  toAnimated(options?: AnimatedUrOptions): AnimatedUr;
  /** A scanner pre-pinned to `replyTypes`; its `parse()` validates the request-id echo. */
  scanner(): TypedUrScanner<TResult>;
}

export function makeSignRequest<TResult>(args: {
  ur: Ur;
  requestId?: Uint8Array;
  replyTypes: readonly string[];
  warnings?: readonly string[];
  context: ChainContext;
  parse: (ur: Ur) => TResult;
}): SignRequest<TResult> {
  const { ur, requestId, replyTypes, context, parse } = args;
  return {
    ur,
    requestId,
    replyTypes,
    warnings: args.warnings ?? [],
    toAnimated: (options?: AnimatedUrOptions) =>
      new AnimatedUr(ur, {
        maxFragmentLength:
          options?.maxFragmentLength ?? context.maxFragmentLength ?? DEFAULT_FRAGMENT_LENGTH,
      }),
    scanner: () => new TypedUrScanner<TResult>({ expectedTypes: replyTypes }, parse),
  };
}

/** Mint or normalize a request id. */
export function resolveRequestId(
  context: ChainContext,
  requestId: Uint8Array | string | undefined,
): Uint8Array {
  return requestId === undefined ? randomRequestId(context.randomBytes) : normalizeRequestId(requestId);
}

/** Accept a reply as a `Ur` object or a single-part `ur:` string. */
export function toUr(input: Ur | string): Ur {
  if (typeof input !== 'string') return input;
  const parsed = parseUrString(input);
  if (parsed.seq !== null) {
    throw new EraSdkError(
      'invalid-props',
      'multi-part UR string: assemble it with the request scanner first',
    );
  }
  return new UrValue(parsed.type, parsed.payload);
}

// ---------------------------------------------------------------------------
// Reply checks: what every `*-signature` must pass before it is a signature.
// ---------------------------------------------------------------------------

export function requireUrType(ur: Ur, expected: readonly string[], what: string): void {
  if (!expected.includes(ur.type)) {
    throw new EraSdkError(
      'wrong-ur-type',
      `unexpected ${what} UR type "${ur.type}", expected ${expected.join(' or ')}`,
      { received: ur.type, expected },
    );
  }
}

export function requireReplyMap(ur: Ur, what: string): CborValue {
  let decoded: CborValue;
  try {
    decoded = cborDecode(ur.cbor);
  } catch (e) {
    throw new EraSdkError('malformed-cbor', `${what} is not readable CBOR: ${(e as Error).message}`);
  }
  const map = asMap(decoded);
  if (!map) throw new EraSdkError('malformed-reply', `${what} is not a CBOR map`);
  return map;
}

/**
 * The reply must echo the request id byte for byte.
 *
 * BYTES, not CBOR values: the device wraps the echo in the UUID tag (37) while
 * requests may send it untagged, so a value-level comparison would reject
 * every genuine reply. An absent echo is a reply that did not come from the
 * request in hand (the device echoes unconditionally when the request carried
 * an id) and is refused rather than tolerated.
 */
export function requireRequestIdEcho(
  map: CborValue,
  key: number,
  expected: Uint8Array | undefined,
  what: string,
): Uint8Array {
  const echoed = mapGet(map, key);
  const value = echoed === undefined ? undefined : stripTags(echoed);
  if (value?.kind !== 'bytes') {
    throw new EraSdkError('malformed-reply', `${what} does not echo the request id (key ${key})`);
  }
  if (expected !== undefined && !equalBytes(value.value, expected)) {
    throw new EraSdkError(
      'request-id-mismatch',
      `${what} echoes a different request id — it answers another sign request, not this one`,
    );
  }
  return value.value;
}

/** A signature whose length is inside `[min, max]`, or a typed refusal. */
export function requireSignatureBytes(
  value: CborValue | undefined,
  what: string,
  min: number,
  max: number,
): Uint8Array {
  const v = value === undefined ? undefined : stripTags(value);
  if (v?.kind !== 'bytes') {
    throw new EraSdkError('malformed-reply', `${what} is missing the signature (key 2)`);
  }
  const length = v.value.length;
  if (length < min || length > max) {
    throw new EraSdkError(
      'malformed-reply',
      `${what} signature is ${length} bytes, expected ${min === max ? `${min}` : `${min}-${max}`}`,
    );
  }
  return v.value;
}
