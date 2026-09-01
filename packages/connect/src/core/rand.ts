import { bytesToHex, hexToBytes } from './bytes';
import { EraSdkError } from './errors';

export type RandomBytesFn = (length: number) => Uint8Array;

/**
 * 16 unpredictable bytes for a sign request id.
 *
 * A CSPRNG output, deliberately NOT a v4/v8 UUID: a UUID spends bits on the
 * wall clock and version fields, leaking the time of signing into the QR and
 * shrinking the unguessable part. The id is what a reply must echo to prove it
 * answers THIS request; it is formatted as a UUID string only where the wire
 * demands one (Tron's `signId`).
 */
export function randomRequestId(randomBytes?: RandomBytesFn): Uint8Array {
  if (randomBytes) {
    const out = randomBytes(16);
    if (!(out instanceof Uint8Array) || out.length !== 16) {
      throw new EraSdkError('no-secure-random', 'randomBytes(16) did not return 16 bytes');
    }
    return out;
  }
  const crypto = (globalThis as { crypto?: { getRandomValues?: (b: Uint8Array) => Uint8Array } })
    .crypto;
  if (crypto?.getRandomValues) {
    const out = new Uint8Array(16);
    crypto.getRandomValues(out);
    return out;
  }
  throw new EraSdkError(
    'no-secure-random',
    'no secure random source: install react-native-get-random-values (React Native) ' +
      'or pass randomBytes in the EraConnect config',
  );
}

/** Render 16 bytes as a lowercase hyphenated UUID string (8-4-4-4-12). */
export function uuidStringify(bytes: Uint8Array): string {
  if (bytes.length !== 16) throw new EraSdkError('invalid-props', 'request id must be 16 bytes');
  const hex = bytesToHex(bytes);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** Accept a request id as 16 raw bytes or a hyphenated/plain 32-hex string. */
export function normalizeRequestId(id: Uint8Array | string): Uint8Array {
  if (id instanceof Uint8Array) {
    if (id.length !== 16) throw new EraSdkError('invalid-props', 'request id must be 16 bytes');
    return new Uint8Array(id);
  }
  const hex = id.replace(/-/g, '');
  if (!/^[0-9a-fA-F]{32}$/.test(hex)) {
    throw new EraSdkError('invalid-props', 'request id string must be a 32-hex UUID');
  }
  return hexToBytes(hex.toLowerCase());
}
