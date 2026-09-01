import { concatBytes, utf8Encode } from '../core/bytes';
import { EraSdkError } from '../core/errors';

/**
 * Minimal protobuf wire codec for the Tron signing envelope. Varint and
 * length-delimited wire types only — the schema uses nothing else.
 *
 * Writer semantics mirror the reference implementation: EXPLICITLY SET fields
 * are written even when they hold default values (a `timestamp` of 0 is
 * `tag, 0x00` on the wire), and fields are emitted in ascending field-number
 * order. Byte-exactness against the golden fixtures depends on both.
 */

export class ProtoWriter {
  private readonly parts: Uint8Array[] = [];

  varintField(field: number, value: number | bigint): this {
    this.parts.push(tag(field, 0), varint(value));
    return this;
  }

  stringField(field: number, value: string): this {
    const bytes = utf8Encode(value);
    this.parts.push(tag(field, 2), varint(bytes.length), bytes);
    return this;
  }

  bytesField(field: number, value: Uint8Array): this {
    this.parts.push(tag(field, 2), varint(value.length), value);
    return this;
  }

  messageField(field: number, encoded: Uint8Array): this {
    this.parts.push(tag(field, 2), varint(encoded.length), encoded);
    return this;
  }

  finish(): Uint8Array {
    return concatBytes(...this.parts);
  }
}

function tag(field: number, wireType: number): Uint8Array {
  return varint((field << 3) | wireType);
}

export function varint(value: number | bigint): Uint8Array {
  let v = typeof value === 'number' ? BigInt(value) : value;
  if (v < 0n) throw new EraSdkError('protobuf-error', 'negative varint');
  const out: number[] = [];
  do {
    let byte = Number(v & 0x7fn);
    v >>= 7n;
    if (v > 0n) byte |= 0x80;
    out.push(byte);
  } while (v > 0n);
  return new Uint8Array(out);
}

export interface ProtoField {
  readonly field: number;
  readonly wireType: number;
  /** Set for wire type 0. */
  readonly value: bigint;
  /** Set for wire type 2 (verbatim slice of the input). */
  readonly bytes: Uint8Array;
}

/**
 * Hardened field reader: varint shift capped, lengths bounds-checked before
 * slicing, unknown fields skippable by wire type, group wire types refused.
 */
export function readFields(bytes: Uint8Array): ProtoField[] {
  const fields: ProtoField[] = [];
  let offset = 0;

  const readVarint = (): bigint => {
    let result = 0n;
    let shift = 0n;
    for (;;) {
      const byte = bytes[offset];
      if (byte === undefined) throw new EraSdkError('protobuf-error', 'truncated varint');
      offset += 1;
      result |= BigInt(byte & 0x7f) << shift;
      if ((byte & 0x80) === 0) return result;
      shift += 7n;
      if (shift > 63n) throw new EraSdkError('protobuf-error', 'varint exceeds 64 bits');
    }
  };

  while (offset < bytes.length) {
    const key = readVarint();
    const field = Number(key >> 3n);
    const wireType = Number(key & 7n);
    if (field === 0) throw new EraSdkError('protobuf-error', 'field number 0');
    switch (wireType) {
      case 0: {
        fields.push({ field, wireType, value: readVarint(), bytes: EMPTY });
        break;
      }
      case 1: {
        if (offset + 8 > bytes.length) throw new EraSdkError('protobuf-error', 'truncated fixed64');
        fields.push({ field, wireType, value: 0n, bytes: bytes.slice(offset, offset + 8) });
        offset += 8;
        break;
      }
      case 2: {
        const length = readVarint();
        if (length > BigInt(bytes.length - offset)) {
          throw new EraSdkError('protobuf-error', 'length-delimited field exceeds input');
        }
        const len = Number(length);
        fields.push({ field, wireType, value: 0n, bytes: bytes.slice(offset, offset + len) });
        offset += len;
        break;
      }
      case 5: {
        if (offset + 4 > bytes.length) throw new EraSdkError('protobuf-error', 'truncated fixed32');
        fields.push({ field, wireType, value: 0n, bytes: bytes.slice(offset, offset + 4) });
        offset += 4;
        break;
      }
      default:
        throw new EraSdkError('protobuf-error', `unsupported wire type ${wireType}`);
    }
  }
  return fields;
}

const EMPTY = new Uint8Array(0);

/** First occurrence of a length-delimited field, or null. */
export function firstBytes(fields: ProtoField[], field: number): Uint8Array | null {
  for (const f of fields) {
    if (f.field === field && f.wireType === 2) return f.bytes;
  }
  return null;
}

/** First occurrence of a varint field, or null. */
export function firstVarint(fields: ProtoField[], field: number): bigint | null {
  for (const f of fields) {
    if (f.field === field && f.wireType === 0) return f.value;
  }
  return null;
}
