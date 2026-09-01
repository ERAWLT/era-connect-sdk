import { bytesToHex, utf8Decode } from '../core/bytes';
import { EraSdkError } from '../core/errors';
import { cborEncode } from './encode';
import type { CborValue } from './model';

/**
 * Hardened CBOR decoder for scanned (attacker-controlled) payloads.
 *
 * Policy, enforced as defaults rather than options:
 *  - definite lengths only (indefinite refused);
 *  - no floats, no simple values beyond bool/null;
 *  - duplicate map keys refused;
 *  - nesting depth capped;
 *  - lengths bounds-checked before any allocation;
 *  - trailing bytes after the top-level item refused.
 *
 * Unknown tags are surfaced as `tag` wrappers, never dropped — the tag-37
 * request-id echo is compared tag-agnostically by the callers.
 */
export function cborDecode(bytes: Uint8Array): CborValue {
  const reader = new Reader(bytes);
  const value = reader.readValue(0);
  if (reader.offset !== bytes.length) {
    throw err('trailing bytes after the top-level item');
  }
  return value;
}

const MAX_DEPTH = 8;

function err(message: string): EraSdkError {
  return new EraSdkError('malformed-cbor', `cbor: ${message}`);
}

class Reader {
  offset = 0;
  constructor(private readonly bytes: Uint8Array) {}

  readValue(depth: number): CborValue {
    if (depth > MAX_DEPTH) throw err('nesting too deep');
    const initial = this.readByte();
    const major = initial >>> 5;
    const info = initial & 0x1f;

    switch (major) {
      case 0:
        return { kind: 'uint', value: this.readArg(info) };
      case 1:
        return { kind: 'nint', value: this.readArg(info) };
      case 2: {
        const len = this.readLength(info);
        return { kind: 'bytes', value: this.readBytes(len) };
      }
      case 3: {
        const len = this.readLength(info);
        const raw = this.readBytes(len);
        let text: string;
        try {
          text = utf8Decode(raw);
        } catch {
          throw err('text string is not valid UTF-8');
        }
        return { kind: 'text', value: text };
      }
      case 4: {
        const len = this.readLength(info);
        if (len > this.bytes.length - this.offset) throw err('array length exceeds input');
        const items: CborValue[] = [];
        for (let i = 0; i < len; i++) items.push(this.readValue(depth + 1));
        return { kind: 'array', items };
      }
      case 5: {
        const len = this.readLength(info);
        if (len * 2 > this.bytes.length - this.offset) throw err('map length exceeds input');
        const entries: [CborValue, CborValue][] = [];
        const seenKeys = new Set<string>();
        for (let i = 0; i < len; i++) {
          const key = this.readValue(depth + 1);
          const keyId = bytesToHex(cborEncode(key));
          if (seenKeys.has(keyId)) throw err('duplicate map key');
          seenKeys.add(keyId);
          entries.push([key, this.readValue(depth + 1)]);
        }
        return { kind: 'map', entries };
      }
      case 6: {
        const tag = this.readArg(info);
        if (tag > 0xffffffffn) throw err('tag exceeds 32 bits');
        return { kind: 'tag', tag: Number(tag), value: this.readValue(depth + 1) };
      }
      case 7: {
        if (info === 20) return { kind: 'bool', value: false };
        if (info === 21) return { kind: 'bool', value: true };
        if (info === 22) return { kind: 'null' };
        throw err(`unsupported simple/float value (info ${info})`);
      }
      default:
        throw err('unreachable major type');
    }
  }

  private readByte(): number {
    const b = this.bytes[this.offset];
    if (b === undefined) throw err('truncated input');
    this.offset += 1;
    return b;
  }

  /** Argument of a head. Refuses indefinite (31) and reserved (28-30). */
  private readArg(info: number): bigint {
    if (info < 24) return BigInt(info);
    if (info === 24) return BigInt(this.readByte());
    if (info === 25) {
      const hi = this.readByte();
      return BigInt((hi << 8) | this.readByte());
    }
    if (info === 26) {
      let v = 0n;
      for (let i = 0; i < 4; i++) v = (v << 8n) | BigInt(this.readByte());
      return v;
    }
    if (info === 27) {
      let v = 0n;
      for (let i = 0; i < 8; i++) v = (v << 8n) | BigInt(this.readByte());
      return v;
    }
    if (info === 31) throw err('indefinite lengths are refused');
    throw err(`reserved additional info ${info}`);
  }

  private readLength(info: number): number {
    const len = this.readArg(info);
    if (len > BigInt(this.bytes.length - this.offset)) throw err('length exceeds input');
    return Number(len);
  }

  private readBytes(length: number): Uint8Array {
    const end = this.offset + length;
    const out = this.bytes.slice(this.offset, end);
    this.offset = end;
    return out;
  }
}
