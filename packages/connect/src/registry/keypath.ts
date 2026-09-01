import type { CborValue } from '../cbor/model';
import { asArray, asBool, asUint, cbArray, cbBool, cbMap, cbTag, cbUint } from '../cbor/model';
import { EraSdkError } from '../core/errors';

/** One BIP-32 derivation level: child index plus the hardened flag (`'`). */
export interface PathLevel {
  readonly index: number;
  readonly hardened: boolean;
}

const PATH_LEVEL = /^(\d+)('?)$/;
const HARDENED_OFFSET = 0x80000000;

/** Parse `m/44'/60'/0'/0/5` into levels. Throws `invalid-props` on anything else. */
export function parsePath(path: string): PathLevel[] {
  if (!path.startsWith('m/')) {
    throw new EraSdkError('invalid-props', `derivation path must start with "m/": ${path}`);
  }
  const segments = path.slice(2).split('/');
  const levels: PathLevel[] = [];
  for (const segment of segments) {
    const match = PATH_LEVEL.exec(segment);
    if (!match) {
      throw new EraSdkError('invalid-props', `bad derivation path segment "${segment}"`);
    }
    const index = Number(match[1]);
    if (!Number.isSafeInteger(index) || index >= HARDENED_OFFSET) {
      throw new EraSdkError('invalid-props', `derivation index out of range in "${segment}"`);
    }
    levels.push({ index, hardened: match[2] === "'" });
  }
  if (levels.length === 0) {
    throw new EraSdkError('invalid-props', 'derivation path has no levels');
  }
  return levels;
}

export function formatPath(levels: readonly PathLevel[]): string {
  return `m/${levels.map((l) => `${l.index}${l.hardened ? "'" : ''}`).join('/')}`;
}

export function pathEquals(a: readonly PathLevel[], b: readonly PathLevel[]): boolean {
  if (a.length !== b.length) return false;
  return a.every((l, i) => l.index === b[i]!.index && l.hardened === b[i]!.hardened);
}

/** Flat `[index, hardened, index, hardened, ...]` component list. */
export function pathComponentsCbor(levels: readonly PathLevel[]): CborValue {
  const items: CborValue[] = [];
  for (const level of levels) {
    items.push(cbUint(level.index), cbBool(level.hardened));
  }
  return cbArray(items);
}

/** A `crypto-keypath` (tag 304): `{1: components, 2: xfp}` (key 2 omitted when no xfp). */
export function keypath304(levels: readonly PathLevel[], xfp?: number): CborValue {
  const entries: [number, CborValue][] = [[1, pathComponentsCbor(levels)]];
  if (xfp !== undefined) entries.push([2, cbUint(xfp)]);
  return cbTag(304, cbMap(entries));
}

/** Parse the flat component list of a `crypto-keypath` back into levels (null on malformed). */
export function parsePathComponents(value: CborValue | undefined): PathLevel[] | null {
  const items = asArray(value);
  if (!items || items.length % 2 !== 0) return null;
  const levels: PathLevel[] = [];
  for (let i = 0; i < items.length; i += 2) {
    const index = asUint(items[i]);
    const hardened = asBool(items[i + 1]);
    if (index === undefined || hardened === undefined || index >= BigInt(HARDENED_OFFSET)) {
      return null;
    }
    levels.push({ index: Number(index), hardened });
  }
  return levels;
}

/** Normalize an xfp given as a u32 int or an 8-hex string into a u32 number. */
export function normalizeXfp(xfp: number | string): number {
  if (typeof xfp === 'number') {
    if (!Number.isSafeInteger(xfp) || xfp < 0 || xfp > 0xffffffff) {
      throw new EraSdkError('invalid-props', 'xfp must be an unsigned 32-bit integer');
    }
    return xfp;
  }
  const hex = xfp.startsWith('0x') ? xfp.slice(2) : xfp;
  if (!/^[0-9a-fA-F]{1,8}$/.test(hex)) {
    throw new EraSdkError('invalid-props', 'xfp string must be up to 8 hex characters');
  }
  return Number.parseInt(hex, 16);
}

/** Lowercase 8-hex form of an xfp (the display / Tron wire form). */
export function xfpToHex(xfp: number): string {
  return xfp.toString(16).padStart(8, '0');
}
