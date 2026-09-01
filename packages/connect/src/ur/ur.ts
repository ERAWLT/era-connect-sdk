import { EraSdkError } from '../core/errors';
import { bytewordsDecode, bytewordsEncode } from './bytewords';

/** An immutable Uniform Resource: a registry type string plus its CBOR payload. */
export class Ur {
  readonly type: string;
  readonly cbor: Uint8Array;

  constructor(type: string, cbor: Uint8Array) {
    if (!/^[a-z][a-z0-9\-]*$/.test(type)) {
      throw new EraSdkError('invalid-props', `"${type}" is not a valid UR type`);
    }
    this.type = type;
    this.cbor = cbor;
  }

  /** The whole UR as one single-part `ur:` string, lowercase (the loggable form). */
  toString(): string {
    return `ur:${this.type}/${bytewordsEncode(this.cbor)}`;
  }

  /** The single-part wire form, uppercase (QR alphanumeric mode). */
  toWireString(): string {
    return this.toString().toUpperCase();
  }
}

const UR_GRAMMAR = /^ur:([a-z\-]+)(\/(\d+-\d+))?\/([a-z]+)$/;

export interface ParsedUrParts {
  readonly type: string;
  /** null for a single-part UR. */
  readonly seq: { readonly num: number; readonly length: number } | null;
  readonly payload: Uint8Array;
}

/**
 * Parse one `ur:` string into (type, sequence, decoded payload).
 *
 * An ABSENT sequence segment means a single-part UR. A segment that is present
 * but unreadable (a number too wide, `0-0`) is a malformed frame and throws —
 * promoting it to "single-part" would send a broken fragment down the branch
 * that completes a scan.
 */
export function parseUrString(text: string): ParsedUrParts {
  const lower = text.toLowerCase();
  const match = UR_GRAMMAR.exec(lower);
  if (!match) {
    throw new EraSdkError('not-a-ur', 'not a ur: string');
  }
  const type = match[1]!;
  const seqSegment = match[3];
  const payload = bytewordsDecode(match[4]!);

  if (seqSegment === undefined) {
    return { type, seq: null, payload };
  }
  const [numText, lengthText] = seqSegment.split('-') as [string, string];
  const num = Number(numText);
  const length = Number(lengthText);
  if (!Number.isSafeInteger(num) || !Number.isSafeInteger(length) || num <= 0 || length <= 0) {
    throw new EraSdkError('malformed-sequence', 'unreadable ur sequence segment');
  }
  return { type, seq: { num, length }, payload };
}

/** The `ur:<type>/` prefix of a frame, without decoding the bytewords body. */
const TYPE_PREFIX = /^ur:([a-z][a-z0-9\-]*)\//;

export function urTypeOf(text: string): string | null {
  const match = TYPE_PREFIX.exec(text.toLowerCase());
  return match ? match[1]! : null;
}
