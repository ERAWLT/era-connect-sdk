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
  readonly xfp: number;
  readonly publicKey: Uint8Array;
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

/** UR types a device links a watch-only wallet with. */
export const WALLET_UR_TYPES: ReadonlySet<string> = new Set([
  'crypto-multi-accounts',
  'crypto-account',
  'crypto-hdkey',
]);

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

  if (!WALLET_UR_TYPES.has(type)) {
    throw new EraSdkError(
      'wrong-ur-type',
      `"${type}" is not a wallet export; expected one of ${[...WALLET_UR_TYPES].join(', ')}`,
      { received: type },
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
  const xfp = asUint(mapGet(origin, 2));
  if (!path || path.length === 0 || xfp === undefined || xfp > 0xffffffffn) return null;

  const publicKey = asBytes(mapGet(map, 3));
  if (!publicKey || (publicKey.length !== 33 && publicKey.length !== 32)) return null;

  const parentFp = asUint(mapGet(map, 8));
  return {
    path,
    xfp: Number(xfp),
    publicKey,
    chainCode: asBytes(mapGet(map, 4)) ?? null,
    parentFingerprint: parentFp !== undefined && parentFp <= 0xffffffffn ? Number(parentFp) : null,
    name: asText(mapGet(map, 9)) ?? null,
    note: asText(mapGet(map, 10)) ?? null,
  };
}
