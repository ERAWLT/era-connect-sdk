import { secp256k1 } from '@noble/curves/secp256k1';
import { sha512 } from '@noble/hashes/sha2';
import { bytesToHex, concatBytes, equalBytes, hexToBytes } from '../core/bytes';
import type { VerifyResult } from './result';
import { failed, unverifiable, verified } from './result';

export interface VerifyXrpSignatureArgs {
  /** The signed binary transaction from the reply. */
  readonly signedTx: Uint8Array;
  /** The `SigningPubKey` hex your request JSON carried (33-byte compressed secp256k1). */
  readonly expectedSigningPubKey: string;
}

/**
 * XRP has no request id — this check IS the binding. The signed binary is
 * split into its canonical fields; `TxnSignature` is removed; the remainder
 * (prefixed with the XRPL signing tag `STX\0`) is hashed with SHA-512-half
 * and the DER signature is verified against `SigningPubKey`, which must also
 * equal the key your request carried.
 *
 * The field walker covers the types Payment-class transactions use; a
 * transaction carrying an exotic field type comes back `checked: false`
 * rather than a false verdict.
 */
export function verifyXrpSignature(args: VerifyXrpSignatureArgs): VerifyResult {
  let fields: XrpField[];
  try {
    fields = splitFields(args.signedTx);
  } catch (e) {
    const message = (e as Error).message;
    if (message === 'unsupported-field') {
      return unverifiable('the transaction carries a field type this checker does not walk');
    }
    return failed(`the signed transaction is not readable: ${message}`);
  }

  const signingPubKey = fields.find((f) => f.header === 0x73);
  const txnSignature = fields.find((f) => f.header === 0x74);
  if (!signingPubKey || !txnSignature) {
    return failed('the signed transaction is missing SigningPubKey or TxnSignature');
  }
  const expected = hexToBytes(args.expectedSigningPubKey);
  if (!equalBytes(signingPubKey.value, expected)) {
    return failed(
      `the transaction was signed with a different key (${bytesToHex(signingPubKey.value)})`,
    );
  }

  // Signing payload: every field except TxnSignature, in the original
  // (canonical) order, behind the 'STX\0' prefix; SHA-512 halved.
  const payload = concatBytes(
    new Uint8Array([0x53, 0x54, 0x58, 0x00]),
    ...fields.filter((f) => f.header !== 0x74).map((f) => f.raw),
  );
  const digest = sha512(payload).slice(0, 32);

  let ok: boolean;
  try {
    ok = secp256k1.verify(
      secp256k1.Signature.fromDER(txnSignature.value).toCompactRawBytes(),
      digest,
      expected,
    );
  } catch (e) {
    return failed(`XRP signature could not be checked: ${(e as Error).message}`);
  }
  return ok ? verified : failed('the signature does not verify against SigningPubKey');
}

interface XrpField {
  /** One-byte header for the common fields (0x73 SigningPubKey, 0x74 TxnSignature). */
  readonly header: number;
  /** The field's VALUE bytes (VL prefix stripped for blob-like types). */
  readonly value: Uint8Array;
  /** The complete encoded field, header + length + value. */
  readonly raw: Uint8Array;
}

/** Split a canonical STObject into its top-level fields. */
function splitFields(bytes: Uint8Array): XrpField[] {
  const fields: XrpField[] = [];
  let pos = 0;
  while (pos < bytes.length) {
    const field = parseField(bytes, pos);
    fields.push(field.field);
    pos = field.end;
  }
  return fields;
}

/** Parse ONE field at `pos`; returns the field and the offset past it. */
function parseField(bytes: Uint8Array, pos: number): { field: XrpField; end: number } {
  const start = pos;
  const first = bytes[pos++];
  if (first === undefined) throw new Error('truncated');
  let type = first >> 4;
  let fieldCode = first & 0x0f;
  if (type === 0) {
    const t = bytes[pos++];
    if (t === undefined) throw new Error('truncated type');
    type = t;
  }
  if (fieldCode === 0) {
    const f = bytes[pos++];
    if (f === undefined) throw new Error('truncated field code');
    fieldCode = f;
  }

  let valueStart = pos;
  switch (type) {
    case 1: // UInt16
      pos += 2;
      break;
    case 2: // UInt32
      pos += 4;
      break;
    case 5: // Hash256
      pos += 32;
      break;
    case 6: {
      // Amount: native XRP = 8 bytes; issued currency = 48 bytes.
      const head = bytes[pos];
      if (head === undefined) throw new Error('truncated amount');
      pos += (head & 0x80) !== 0 ? 48 : 8;
      break;
    }
    case 7: // Blob (VL)
    case 8: {
      // AccountID (VL)
      const vl = readVl(bytes, pos);
      valueStart = vl.next;
      pos = vl.next + vl.length;
      break;
    }
    case 14: {
      // STObject: nested fields until the end marker 0xE1.
      while (bytes[pos] !== 0xe1) {
        if (pos >= bytes.length) throw new Error('unterminated inner object');
        pos = parseField(bytes, pos).end;
      }
      pos += 1;
      break;
    }
    case 15: {
      // STArray: a sequence of inner-object fields until 0xF1.
      while (bytes[pos] !== 0xf1) {
        if (pos >= bytes.length) throw new Error('unterminated array');
        pos = parseField(bytes, pos).end;
      }
      pos += 1;
      break;
    }
    default:
      throw new Error('unsupported-field');
  }
  if (pos > bytes.length) throw new Error('truncated field');
  return {
    field: {
      header: (type << 4) | (fieldCode <= 15 ? fieldCode : 0),
      value: bytes.slice(valueStart, pos),
      raw: bytes.slice(start, pos),
    },
    end: pos,
  };
}

/** XRPL variable-length prefix. */
function readVl(bytes: Uint8Array, pos: number): { length: number; next: number } {
  const b1 = bytes[pos];
  if (b1 === undefined) throw new Error('truncated length');
  if (b1 <= 192) return { length: b1, next: pos + 1 };
  if (b1 <= 240) {
    const b2 = bytes[pos + 1];
    if (b2 === undefined) throw new Error('truncated length');
    return { length: 193 + (b1 - 193) * 256 + b2, next: pos + 2 };
  }
  const b2 = bytes[pos + 1];
  const b3 = bytes[pos + 2];
  if (b2 === undefined || b3 === undefined) throw new Error('truncated length');
  return { length: 12481 + (b1 - 241) * 65536 + b2 * 256 + b3, next: pos + 3 };
}
