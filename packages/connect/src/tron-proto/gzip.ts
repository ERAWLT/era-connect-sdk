import { Gunzip, gzipSync } from 'fflate';
import { concatBytes } from '../core/bytes';
import { EraSdkError } from '../core/errors';
import { crc32 } from '../ur/crc32';

/** Smallest possible gzip stream: 10-byte header + 8-byte trailer. */
const MIN_GZIP_BYTES = 18;

/** Bytes fed to the inflater per step; bounds the overshoot past the cap. */
const SLICE_BYTES = 1024;

/** Deterministic gzip (fixed level, zeroed mtime) for reproducible request bytes. */
export function gzipCompress(data: Uint8Array): Uint8Array {
  return gzipSync(data, { level: 9, mtime: 0 });
}

/**
 * Inflate with a hard output ceiling.
 *
 * A one-shot gunzip allocates the entire output before anyone can refuse it —
 * gzip reaches ~1000:1 in practice, so a few hundred scanned bytes could ask
 * for an arbitrary allocation. The decoder is therefore driven in slices and
 * the output counted as it arrives; the moment the total would pass the cap,
 * feeding stops and the reply is refused.
 *
 * The trailer's ISIZE (declared inflated length) is used twice: as a cheap
 * refusal of honest bombs before any work, and as a truncation check at the
 * end — an inflater hands back a partial buffer for a truncated stream
 * without erroring, and a genuine device reply always declares honestly.
 */
export function gunzipCapped(data: Uint8Array, maxOutputBytes: number): Uint8Array {
  if (data.length < MIN_GZIP_BYTES) {
    throw new EraSdkError('gzip-error', 'compressed payload is too short to be a gzip stream');
  }
  if (data[0] !== 0x1f || data[1] !== 0x8b) {
    throw new EraSdkError('gzip-error', 'compressed payload is not a gzip stream');
  }
  const n = data.length;
  const isize =
    (data[n - 4]! | (data[n - 3]! << 8) | (data[n - 2]! << 16) | (data[n - 1]! << 24)) >>> 0;
  if (isize > maxOutputBytes) {
    throw new EraSdkError(
      'gzip-error',
      `compressed payload declares ${isize} bytes, over the ${maxOutputBytes} byte ceiling`,
    );
  }

  const chunks: Uint8Array[] = [];
  let total = 0;
  let overflowed = false;
  let malformed: string | null = null;

  const gunzip = new Gunzip((chunk) => {
    if (overflowed) return;
    if (total + chunk.length > maxOutputBytes) {
      overflowed = true;
      return;
    }
    chunks.push(chunk);
    total += chunk.length;
  });

  try {
    for (let offset = 0; offset < n && !overflowed; offset += SLICE_BYTES) {
      const end = Math.min(offset + SLICE_BYTES, n);
      const isLast = end === n;
      gunzip.push(data.slice(offset, end), isLast);
    }
  } catch (e) {
    malformed = (e as Error).message ?? 'inflate error';
  }

  if (overflowed) {
    throw new EraSdkError(
      'gzip-error',
      `compressed payload inflates past the ${maxOutputBytes} byte ceiling`,
    );
  }
  if (malformed !== null) {
    throw new EraSdkError('gzip-error', `compressed payload is malformed: ${malformed}`);
  }
  const out = concatBytes(...chunks);
  if (out.length !== isize) {
    throw new EraSdkError(
      'gzip-error',
      `compressed payload inflated to ${out.length} bytes but declares ${isize} — truncated or malformed`,
    );
  }
  // The trailer CRC32 (little-endian, bytes n-8..n-5) must cover the inflated
  // output. The streaming inflater does not verify it, and the reference
  // implementation's native decoder does — without this check a corrupted
  // stream, or a CONCATENATED multi-member stream (whose final member's CRC
  // cannot cover the whole output), would be accepted here and refused there.
  const declaredCrc =
    (data[n - 8]! | (data[n - 7]! << 8) | (data[n - 6]! << 16) | (data[n - 5]! << 24)) >>> 0;
  if (crc32(out) !== declaredCrc) {
    throw new EraSdkError('gzip-error', 'compressed payload is malformed: CRC mismatch');
  }
  return out;
}
