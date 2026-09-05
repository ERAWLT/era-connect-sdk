import { cborDecode } from '../cbor/decode';
import type { CborValue } from '../cbor/model';
import { asArray, asBytes, asMap, asText, asUint, mapGet } from '../cbor/model';
import { EraSdkError } from '../core/errors';
import { parseUrString, type Ur } from '../ur/ur';
import type { PathLevel } from './keypath';
import { parsePathComponents } from './keypath';

/**
 * Raw account entry parsed from a `crypto-multi-accounts` (1103) export.
 *
 * `xfp` is the entry's ORIGIN source fingerprint (`crypto-keypath` key 2) —
 * the value a `*-sign-request` keypath must carry. It is NOT the top-level
 * master fingerprint, although the two often coincide.
 */
export interface RawAccountEntry {
  readonly path: readonly PathLevel[];
  /**
   * The origin's source fingerprint, when the export carries one. Cardano
   * entries deliberately ship a path-only origin — resolve against the
   * wrapper's master fingerprint in that case.
   */
  readonly xfp: number | null;
  /**
   * Nullable and length-unconstrained, as in the reference implementation: an
   * entry without a usable key still resolves its xfp for signing — only the
   * address-derivation views require the 33/32-byte forms.
   */
  readonly publicKey: Uint8Array | null;
  readonly chainCode: Uint8Array | null;
  readonly parentFingerprint: number | null;
  readonly name: string | null;
  /** A label string (`account.standard`, ...) — NEVER chain metadata. */
  readonly note: string | null;
}

export interface RawMultiAccounts {
  readonly masterFingerprint: number;
  readonly deviceName: string | null;
  readonly deviceId: string | null;
  readonly deviceVersion: string | null;
  readonly entries: readonly RawAccountEntry[];
}

/**
 * UR types a device links a watch-only wallet with — drop it straight into a
 * scanner's `expectedTypes`.
 *
 * A FROZEN array, not a `Set`: `ReadonlySet` is erased at compile time, so an
 * exported `Set` is a live one at runtime and `WALLET_UR_TYPES.add(...)`
 * — no cast required — would widen the type gate below for the whole process.
 * The gate keeps its own `Set`, built once from this array and unreachable
 * from outside this module.
 */
export const WALLET_UR_TYPES: readonly string[] = Object.freeze([
  'crypto-multi-accounts',
  'crypto-account',
  'crypto-hdkey',
]);

/**
 * The gate's own copy — private, and never handed out. It is DERIVED from the
 * array above and must stay that way: an advertised list that admits three
 * types while the gate enforces four is the hazard this split introduced in
 * place of the mutable-Set one. Nothing in the type system pairs them, so the
 * pairing is asserted behaviourally, in both directions, by "advertises
 * exactly the types its private gate enforces" in `test/public-surface.test.ts`.
 */
const WALLET_UR_TYPE_SET: ReadonlySet<string> = new Set(WALLET_UR_TYPES);

/**
 * Parse a wallet-export UR.
 *
 * Of the three admitted link types only the `crypto-multi-accounts` shape
 * yields derivable accounts; an export that yields none is refused rather
 * than stored as an unusable wallet. Malformed entries are skipped
 * individually so one foreign item does not abort the rest.
 */
export function parseMultiAccountsUr(input: Ur | string): RawMultiAccounts {
  let type: string;
  let cbor: Uint8Array;
  if (typeof input === 'string') {
    const parsed = parseUrString(input);
    if (parsed.seq !== null) {
      throw new EraSdkError(
        'invalid-props',
        'multi-part UR string: assemble it with a UrScanner first',
      );
    }
    type = parsed.type;
    cbor = parsed.payload;
  } else {
    type = input.type;
    cbor = input.cbor;
  }

  if (!WALLET_UR_TYPE_SET.has(type)) {
    // The type is attacker-sized (the UR grammar allows an unbounded letter
    // run) — truncate before it reaches a message or error data.
    const shown = type.length > 32 ? `${type.slice(0, 32)}…` : type;
    throw new EraSdkError(
      'wrong-ur-type',
      `"${shown}" is not a wallet export; expected one of ${WALLET_UR_TYPES.join(', ')}`,
      { received: shown },
    );
  }

  let decoded: CborValue;
  try {
    decoded = cborDecode(cbor);
  } catch (e) {
    throw new EraSdkError('malformed-cbor', `cannot decode wallet UR: ${(e as Error).message}`);
  }
  const root = asMap(decoded);
  if (!root) {
    throw new EraSdkError('malformed-cbor', 'wallet UR is not a CBOR map');
  }

  // A standalone `crypto-hdkey` export (the single-account link some wallet
  // profiles use — e.g. the TON one: `{3: key, 6: keypath, 10: name}`) IS the
  // entry map itself: no master-fingerprint/list wrapper. The entry's origin
  // fingerprint doubles as the master fingerprint.
  if (type === 'crypto-hdkey') {
    const entry = tryParseEntry(decoded);
    if (!entry) {
      throw new EraSdkError(
        'malformed-reply',
        'crypto-hdkey export carries no derivable account (missing origin keypath)',
      );
    }
    return {
      masterFingerprint: entry.xfp ?? 0,
      deviceName: null,
      deviceId: null,
      deviceVersion: null,
      entries: [entry],
    };
  }

  const master = asUint(mapGet(root, 1));
  const list = asArray(mapGet(root, 2));
  if (master === undefined || !list) {
    throw new EraSdkError(
      'malformed-reply',
      'wallet UR missing master fingerprint (key 1) or accounts (key 2)',
    );
  }

  const entries: RawAccountEntry[] = [];
  for (const item of list) {
    const entry = tryParseEntry(item);
    if (entry) entries.push(entry);
  }
  if (entries.length === 0) {
    throw new EraSdkError(
      'malformed-reply',
      'wallet UR carries no account this SDK can derive an address from',
    );
  }

  return {
    masterFingerprint: Number(master & 0xffffffffn),
    deviceName: asText(mapGet(root, 3)) ?? null,
    deviceId: asText(mapGet(root, 4)) ?? null,
    deviceVersion: asText(mapGet(root, 5)) ?? null,
    entries,
  };
}

function tryParseEntry(item: CborValue): RawAccountEntry | null {
  const map = asMap(item);
  if (!map) return null;
  const origin = asMap(mapGet(map, 6));
  if (!origin) return null;

  const path = parsePathComponents(mapGet(origin, 1));
  if (!path || path.length === 0) return null;
  const xfpValue = asUint(mapGet(origin, 2));
  const xfp = xfpValue !== undefined && xfpValue <= 0xffffffffn ? Number(xfpValue) : null;

  const parentFp = asUint(mapGet(map, 8));
  return {
    path,
    xfp,
    publicKey: asBytes(mapGet(map, 3)) ?? null,
    chainCode: asBytes(mapGet(map, 4)) ?? null,
    parentFingerprint: parentFp !== undefined && parentFp <= 0xffffffffn ? Number(parentFp) : null,
    name: asText(mapGet(map, 9)) ?? null,
    note: asText(mapGet(map, 10)) ?? null,
  };
}
