import { EraSdkError } from '../core/errors';

/**
 * CashAddr codec (the Bitcoin Cash address format).
 *
 * Not bech32: the checksum is a 40-bit BCH code over its own generator set,
 * and there is no separator-position rule — the payload is everything after
 * the optional `prefix:`. The decoder takes every spec-legal spelling
 * (bare, prefixed, all-uppercase; mixed case refused), but the DEVICE's own
 * parser reads only the lowercase form — its prefix rebuild turns an
 * uppercase body into a mixed-case string it then rejects, and the refusal
 * fails open into a zero hash. Anything that goes on the wire must therefore
 * be re-encoded through `encodeCashAddr`, never passed through verbatim;
 * `BchChain.generateSignRequest` does exactly that.
 */

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

const CHARSET_REV = new Map<string, number>([...CHARSET].map((c, i) => [c, i]));

/** The default (mainnet) human-readable prefix. */
export const CASHADDR_PREFIX = 'bitcoincash';

const GENERATOR = [0x98f2bc8e61n, 0x79b76d99e2n, 0xf33e5fb3c4n, 0xae2eabe2a8n, 0x1e4f43e470n];

function polymod(values: readonly number[]): bigint {
  let c = 1n;
  for (const d of values) {
    const c0 = c >> 35n;
    c = ((c & 0x07ffffffffn) << 5n) ^ BigInt(d);
    for (let i = 0; i < 5; i++) {
      if ((c0 >> BigInt(i)) & 1n) c ^= GENERATOR[i]!;
    }
  }
  return c ^ 1n;
}

/** Prefix expansion: the low five bits of each character, then a zero. */
function expandPrefix(prefix: string): number[] {
  const out: number[] = [];
  for (const ch of prefix) out.push(ch.charCodeAt(0) & 0x1f);
  out.push(0);
  return out;
}

function convertBits(data: readonly number[], from: number, to: number, pad: boolean): number[] {
  let acc = 0;
  let bits = 0;
  const out: number[] = [];
  const maxv = (1 << to) - 1;
  for (const value of data) {
    if (value < 0 || value >> from !== 0) {
      throw new EraSdkError('invalid-props', 'cashaddr: value out of range');
    }
    acc = (acc << from) | value;
    bits += from;
    while (bits >= to) {
      bits -= to;
      out.push((acc >> bits) & maxv);
    }
  }
  if (pad) {
    if (bits > 0) out.push((acc << (to - bits)) & maxv);
  } else if (bits >= from || ((acc << (to - bits)) & maxv) !== 0) {
    throw new EraSdkError('invalid-props', 'cashaddr: invalid padding');
  }
  return out;
}

export type CashAddrType = 'p2pkh' | 'p2sh';

export interface CashAddrPayload {
  readonly type: CashAddrType;
  /** The 20-byte hash160. */
  readonly hash: Uint8Array;
  readonly prefix: string;
}

/**
 * Decode a CashAddr, with or without its `prefix:`. Only 20-byte P2PKH and
 * P2SH payloads are accepted — those are the two script kinds the device
 * builds outputs for.
 */
export function decodeCashAddr(address: string, expectedPrefix = CASHADDR_PREFIX): CashAddrPayload {
  // ASCII only, before any case folding: the case guard below is ASCII-scoped,
  // while String.toLowerCase folds full Unicode — U+212A KELVIN SIGN would
  // otherwise slip past the guard and fold into a charset 'k'.
  if (!/^[0-9A-Za-z:]*$/.test(address)) {
    throw new EraSdkError('invalid-props', 'cashaddr: invalid character');
  }
  const hasUpper = /[A-Z]/.test(address);
  const hasLower = /[a-z]/.test(address);
  if (hasUpper && hasLower) {
    throw new EraSdkError('invalid-props', 'cashaddr: mixed-case address refused');
  }
  const lower = address.toLowerCase();
  const colon = lower.lastIndexOf(':');
  const prefix = colon === -1 ? expectedPrefix : lower.slice(0, colon);
  const payload = colon === -1 ? lower : lower.slice(colon + 1);
  if (prefix !== expectedPrefix) {
    throw new EraSdkError(
      'invalid-props',
      `cashaddr: prefix "${prefix}" does not match expected "${expectedPrefix}"`,
    );
  }
  if (payload.length < 8 + 1) {
    throw new EraSdkError('invalid-props', 'cashaddr: payload too short');
  }
  const values: number[] = [];
  for (const ch of payload) {
    const v = CHARSET_REV.get(ch);
    if (v === undefined) {
      throw new EraSdkError('invalid-props', `cashaddr: invalid character "${ch}"`);
    }
    values.push(v);
  }
  if (polymod([...expandPrefix(prefix), ...values]) !== 0n) {
    throw new EraSdkError('invalid-props', 'cashaddr: checksum mismatch');
  }
  const data = convertBits(values.slice(0, -8), 5, 8, false);
  if (data.length === 0) {
    throw new EraSdkError('invalid-props', 'cashaddr: empty payload');
  }
  const version = data[0]!;
  if (version & 0x80) {
    throw new EraSdkError('invalid-props', 'cashaddr: reserved version bit set');
  }
  const typeBits = (version >> 3) & 0x0f;
  const sizeBits = version & 0x07;
  const HASH_SIZES = [160, 192, 224, 256, 320, 384, 448, 512];
  const hashBits = HASH_SIZES[sizeBits]!;
  if (data.length - 1 !== hashBits / 8) {
    throw new EraSdkError('invalid-props', 'cashaddr: hash length does not match version byte');
  }
  if (typeBits !== 0 && typeBits !== 1) {
    throw new EraSdkError('invalid-props', `cashaddr: unsupported address type ${typeBits}`);
  }
  if (hashBits !== 160) {
    throw new EraSdkError('invalid-props', 'cashaddr: only 20-byte hashes are supported');
  }
  return {
    type: typeBits === 0 ? 'p2pkh' : 'p2sh',
    hash: Uint8Array.from(data.slice(1)),
    prefix,
  };
}

/** Encode a 20-byte hash160 as a CashAddr. Returns the bare form by default. */
export function encodeCashAddr(
  type: CashAddrType,
  hash: Uint8Array,
  options?: { prefix?: string | undefined; withPrefix?: boolean | undefined },
): string {
  if (hash.length !== 20) {
    throw new EraSdkError('invalid-props', 'cashaddr: hash must be 20 bytes');
  }
  const prefix = options?.prefix ?? CASHADDR_PREFIX;
  const version = type === 'p2pkh' ? 0 : 8; // typeBits<<3 | sizeBits(160 -> 0)
  const payload = convertBits([version, ...hash], 8, 5, true);
  const checksumInput = [...expandPrefix(prefix), ...payload, 0, 0, 0, 0, 0, 0, 0, 0];
  const checksum = polymod(checksumInput);
  const suffix: number[] = [];
  for (let i = 7; i >= 0; i--) suffix.push(Number((checksum >> BigInt(5 * i)) & 0x1fn));
  const body = [...payload, ...suffix].map((v) => CHARSET[v]!).join('');
  return options?.withPrefix ? `${prefix}:${body}` : body;
}
