import { concatBytes, utf8Encode } from '../core/bytes';
import { EraSdkError } from '../core/errors';
import type { CborValue } from './model';

/**
 * Deterministic CBOR encoder: definite lengths only, minimal-width integer
 * heads, map entries in insertion order. This matches, byte for byte, what the
 * reference implementation produces and what the device firmware parses — the
 * exact bytes are pinned by golden-vector tests, which is why this encoder is
 * hand-rolled rather than delegated to a dependency's release cadence.
 *
 * It deliberately cannot emit floats, indefinite lengths or exotic simple
 * values: the protocol never uses them.
 */
export function cborEncode(value: CborValue): Uint8Array {
  const parts: Uint8Array[] = [];
  writeValue(value, parts, 0);
  return concatBytes(...parts);
}

const MAX_DEPTH = 8;

function writeValue(value: CborValue, parts: Uint8Array[], depth: number): void {
  if (depth > MAX_DEPTH) {
    throw new EraSdkError('malformed-cbor', 'cbor encode: nesting too deep');
  }
  switch (value.kind) {
    case 'uint':
      parts.push(head(0, value.value));
      return;
    case 'nint': {
      if (value.value < 0n) throw new EraSdkError('malformed-cbor', 'nint holds the magnitude');
      parts.push(head(1, value.value));
      return;
    }
    case 'bytes':
      parts.push(head(2, BigInt(value.value.length)), value.value);
      return;
    case 'text': {
      const utf8 = utf8Encode(value.value);
      parts.push(head(3, BigInt(utf8.length)), utf8);
      return;
    }
    case 'array': {
      parts.push(head(4, BigInt(value.items.length)));
      for (const item of value.items) writeValue(item, parts, depth + 1);
      return;
    }
    case 'map': {
      parts.push(head(5, BigInt(value.entries.length)));
      for (const [k, v] of value.entries) {
        writeValue(k, parts, depth + 1);
        writeValue(v, parts, depth + 1);
      }
      return;
    }
    case 'tag':
      parts.push(head(6, BigInt(value.tag)));
      writeValue(value.value, parts, depth + 1);
      return;
    case 'bool':
      parts.push(new Uint8Array([value.value ? 0xf5 : 0xf4]));
      return;
    case 'null':
      parts.push(new Uint8Array([0xf6]));
      return;
  }
}

/** Major-type head with a minimal-width argument. */
function head(major: number, arg: bigint): Uint8Array {
  if (arg < 0n) throw new EraSdkError('malformed-cbor', 'cbor head: negative argument');
  const m = major << 5;
  if (arg < 24n) return new Uint8Array([m | Number(arg)]);
  if (arg <= 0xffn) return new Uint8Array([m | 24, Number(arg)]);
  if (arg <= 0xffffn) {
    const n = Number(arg);
    return new Uint8Array([m | 25, n >>> 8, n & 0xff]);
  }
  if (arg <= 0xffffffffn) {
    const n = Number(arg);
    return new Uint8Array([
      m | 26,
      (n >>> 24) & 0xff,
      (n >>> 16) & 0xff,
      (n >>> 8) & 0xff,
      n & 0xff,
    ]);
  }
  if (arg <= 0xffffffffffffffffn) {
    const out = new Uint8Array(9);
    out[0] = m | 27;
    let v = arg;
    for (let i = 8; i >= 1; i--) {
      out[i] = Number(v & 0xffn);
      v >>= 8n;
    }
    return out;
  }
  throw new EraSdkError('malformed-cbor', 'cbor head: argument exceeds 64 bits');
}
