/** Byte helpers. `Uint8Array` end-to-end; no Buffer, no Node built-ins. */

export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

/** Constant-shape byte equality (length check + full loop). */
export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

/** Big-endian unsigned 32-bit. */
export function u32be(value: number): Uint8Array {
  const out = new Uint8Array(4);
  out[0] = (value >>> 24) & 0xff;
  out[1] = (value >>> 16) & 0xff;
  out[2] = (value >>> 8) & 0xff;
  out[3] = value & 0xff;
  return out;
}

const HEX_CHARS = '0123456789abcdef';

export function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += HEX_CHARS[b >>> 4]! + HEX_CHARS[b & 0x0f]!;
  return out;
}

export function hexToBytes(hex: string): Uint8Array {
  let h = hex;
  if (h.startsWith('0x') || h.startsWith('0X')) h = h.slice(2);
  if (h.length % 2 !== 0) throw new Error('hex string has odd length');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(h.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new Error('hex string has non-hex characters');
    out[i] = byte;
  }
  return out;
}

/** Minimal-width big-endian bytes of a non-negative bigint (empty for 0n is NOT produced; 0n -> [0]). */
export function bigintToBytes(value: bigint): Uint8Array {
  if (value < 0n) throw new Error('negative bigint');
  if (value === 0n) return new Uint8Array([0]);
  let hex = value.toString(16);
  if (hex.length % 2 === 1) hex = `0${hex}`;
  return hexToBytes(hex);
}

export function bytesToBigint(bytes: Uint8Array): bigint {
  let out = 0n;
  for (const b of bytes) out = (out << 8n) | BigInt(b);
  return out;
}

/** UTF-8 encode without TextEncoder (absent on older Hermes). */
export function utf8Encode(text: string): Uint8Array {
  const out: number[] = [];
  for (let i = 0; i < text.length; i++) {
    let code = text.charCodeAt(i);
    if (code < 0x80) {
      out.push(code);
    } else if (code < 0x800) {
      out.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
    } else if (code < 0xd800 || code >= 0xe000) {
      out.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
    } else {
      i++;
      if (i >= text.length) throw new Error('unpaired surrogate in string');
      const next = text.charCodeAt(i);
      code = 0x10000 + (((code & 0x3ff) << 10) | (next & 0x3ff));
      out.push(
        0xf0 | (code >> 18),
        0x80 | ((code >> 12) & 0x3f),
        0x80 | ((code >> 6) & 0x3f),
        0x80 | (code & 0x3f),
      );
    }
  }
  return new Uint8Array(out);
}

/**
 * STRICT UTF-8 decode without TextDecoder (absent on older Hermes). Throws on
 * malformed input, including overlong encodings, surrogate code points and
 * values past U+10FFFF — a lenient decoder would let a hostile reply smuggle
 * bytes that render as different text than they compare as.
 */
export function utf8Decode(bytes: Uint8Array): string {
  let out = '';
  let i = 0;
  while (i < bytes.length) {
    const b0 = bytes[i]!;
    if (b0 < 0x80) {
      out += String.fromCharCode(b0);
      i += 1;
      continue;
    }
    let extra: number;
    let code: number;
    let minCode: number;
    if ((b0 & 0xe0) === 0xc0) {
      extra = 1;
      code = b0 & 0x1f;
      minCode = 0x80;
    } else if ((b0 & 0xf0) === 0xe0) {
      extra = 2;
      code = b0 & 0x0f;
      minCode = 0x800;
    } else if ((b0 & 0xf8) === 0xf0) {
      extra = 3;
      code = b0 & 0x07;
      minCode = 0x10000;
    } else {
      throw new Error('malformed UTF-8'); // continuation or F8-FF lead byte
    }
    if (i + extra >= bytes.length) throw new Error('truncated UTF-8');
    for (let k = 1; k <= extra; k++) {
      const bk = bytes[i + k]!;
      if ((bk & 0xc0) !== 0x80) throw new Error('malformed UTF-8 continuation');
      code = (code << 6) | (bk & 0x3f);
    }
    if (code < minCode) throw new Error('overlong UTF-8 encoding');
    if (code >= 0xd800 && code <= 0xdfff) throw new Error('UTF-8 encodes a surrogate');
    if (code > 0x10ffff) throw new Error('UTF-8 code point out of range');
    if (code > 0xffff) {
      code -= 0x10000;
      out += String.fromCharCode(0xd800 + (code >> 10), 0xdc00 + (code & 0x3ff));
    } else {
      out += String.fromCharCode(code);
    }
    i += 1 + extra;
  }
  return out;
}

/** ASCII decode (used for replies that carry text as raw bytes). Throws on non-ASCII. */
export function asciiDecode(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) {
    if (b > 0x7f) throw new Error('non-ASCII byte');
    out += String.fromCharCode(b);
  }
  return out;
}
