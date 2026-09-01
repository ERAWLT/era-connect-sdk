import { sha256 } from '@noble/hashes/sha2';
import { concatBytes } from '../core/bytes';
import { EraSdkError } from '../core/errors';

/**
 * Minimal TON Bag-of-Cells reader + cell representation hash — exactly the
 * subset the device's signer implements: generic BoC, ordinary level-0 cells,
 * first root. The transaction digest the device signs IS the root cell's
 * representation hash, so this must agree with the firmware bit for bit.
 *
 * Hardened for scanned/untrusted input: size caps, bounds checks, and
 * forward-only references (the standard BoC topological order; a backward
 * reference would make the single-pass hash read an uncomputed child).
 */

const BOC_MAGIC = 0xb5ee9c72;
const MAX_CELLS = 256;
const MAX_CELL_DATA_BYTES = 128;
const MAX_REFS = 4;

interface Cell {
  dataBits: number;
  data: Uint8Array;
  refs: number[];
  depth: number;
  hash: Uint8Array;
}

function err(message: string): EraSdkError {
  return new EraSdkError('malformed-reply', `ton boc: ${message}`);
}

/** Representation hash of the ROOT cell of a BoC — the bytes TON signs. */
export function bocRootHash(boc: Uint8Array): Uint8Array {
  if (boc.length < 10) throw err('too short');
  const magic = ((boc[0]! << 24) | (boc[1]! << 16) | (boc[2]! << 8) | boc[3]!) >>> 0;
  if (magic !== BOC_MAGIC) throw err('not a generic BoC');

  const flags = boc[4]!;
  const hasIdx = (flags >> 7) & 1;
  const refSize = flags & 0x07;
  const offSize = boc[5]!;
  if (refSize === 0 || refSize > 4) throw err('bad ref size');
  if (offSize === 0 || offSize > 8) throw err('bad offset size');

  let pos = 6;
  const readInt = (byteLen: number): number => {
    let value = 0;
    for (let i = 0; i < byteLen; i++) {
      if (pos >= boc.length) throw err('truncated header');
      value = value * 256 + boc[pos++]!;
    }
    if (!Number.isSafeInteger(value)) throw err('header value out of range');
    return value;
  };

  const cellCount = readInt(refSize);
  const rootCount = readInt(refSize);
  readInt(refSize); // absent count
  readInt(offSize); // total cell data size
  if (rootCount === 0) throw err('no roots');
  if (cellCount === 0 || cellCount > MAX_CELLS) throw err('cell count out of range');

  const rootIndex = readInt(refSize);
  for (let i = 1; i < rootCount; i++) readInt(refSize); // remaining root indices
  if (rootIndex >= cellCount) throw err('root index out of range');
  if (hasIdx) pos += cellCount * offSize; // skip the offsets index

  const cells: Cell[] = [];
  for (let i = 0; i < cellCount; i++) {
    if (pos + 2 > boc.length) throw err('truncated cell');
    const d1 = boc[pos++]!;
    const d2 = boc[pos++]!;
    const refCount = d1 & 0x07;
    if (refCount > MAX_REFS) throw err('too many references');

    const dataByteLen = (d2 + 1) >> 1;
    const incomplete = (d2 & 1) === 1;
    if (dataByteLen > MAX_CELL_DATA_BYTES) throw err('cell data too large');
    if (pos + dataByteLen > boc.length) throw err('truncated cell data');
    const data = boc.slice(pos, pos + dataByteLen);
    pos += dataByteLen;

    // Bit length from the completion tag (last set bit marks the end).
    let dataBits: number;
    if (incomplete && dataByteLen > 0) {
      const last = data[dataByteLen - 1]!;
      if (last === 0) {
        dataBits = (dataByteLen - 1) * 8;
      } else {
        let trailingZeros = 0;
        for (let b = 0; b < 8; b++) {
          if (last & (1 << b)) break;
          trailingZeros++;
        }
        dataBits = dataByteLen * 8 - 1 - trailingZeros;
      }
    } else {
      dataBits = dataByteLen * 8;
    }

    const refs: number[] = [];
    for (let r = 0; r < refCount; r++) {
      const ref = readInt(refSize);
      if (ref >= cellCount) throw err('reference out of range');
      if (ref <= i) throw err('non-topological cell reference');
      refs.push(ref);
    }
    cells.push({ dataBits, data, refs, depth: 0, hash: new Uint8Array(0) });
  }

  // Bottom-up (children first — guaranteed by the forward-only reference check).
  for (let i = cellCount - 1; i >= 0; i--) {
    const cell = cells[i]!;
    let maxChildDepth = -1;
    for (const r of cell.refs) {
      maxChildDepth = Math.max(maxChildDepth, cells[r]!.depth);
    }
    cell.depth = cell.refs.length === 0 ? 0 : maxChildDepth + 1;

    const dataBytes = (cell.dataBits + 7) >> 3;
    const incomplete = cell.dataBits % 8 !== 0;
    const repr: number[] = [cell.refs.length, dataBytes * 2 - (incomplete ? 1 : 0)];
    for (let b = 0; b < dataBytes; b++) repr.push(cell.data[b] ?? 0);
    if (incomplete && dataBytes > 0) {
      const shift = 7 - (cell.dataBits % 8);
      const last = repr.length - 1;
      repr[last] = (repr[last]! | (1 << shift)) & (0xff << shift) & 0xff;
    }
    for (const r of cell.refs) {
      repr.push((cells[r]!.depth >> 8) & 0xff, cells[r]!.depth & 0xff);
    }
    let bytes: Uint8Array = new Uint8Array(repr);
    for (const r of cell.refs) bytes = concatBytes(bytes, cells[r]!.hash);
    cell.hash = sha256(bytes);
  }

  return cells[rootIndex]!.hash;
}
