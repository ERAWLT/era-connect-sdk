import { EraSdkError } from '../core/errors';

/**
 * Minimal PSBT v0 (BIP-174) reader — just enough structure for the
 * verification guard: the global unsigned transaction (verbatim slice, never
 * re-serialized), the PSBT version, and per-input key/value maps.
 *
 * Hardened: compact-size lengths bounds-checked before slicing, duplicate
 * keys within one map refused (a hostile PSBT carrying two final scriptSigs
 * for one input must not survive parsing).
 */

export interface PsbtKeyValue {
  readonly keyType: number;
  readonly keyData: Uint8Array;
  readonly value: Uint8Array;
}

export interface ParsedPsbt {
  /** The global UNSIGNED_TX value, verbatim. */
  readonly unsignedTx: Uint8Array;
  /** Global PSBT_GLOBAL_VERSION (0xFB) if present; v0 files normally omit it. */
  readonly version: number;
  readonly inputs: readonly (readonly PsbtKeyValue[])[];
  readonly outputs: readonly (readonly PsbtKeyValue[])[];
}

const MAGIC = [0x70, 0x73, 0x62, 0x74, 0xff]; // "psbt\xff"

export const PsbtInputType = {
  partialSig: 0x02,
  finalScriptSig: 0x07,
  finalScriptWitness: 0x08,
  taprootKeySpendSignature: 0x13,
  taprootScriptSpendSignature: 0x14,
} as const;

function err(message: string): EraSdkError {
  return new EraSdkError('malformed-reply', `psbt: ${message}`);
}

class Reader {
  offset = 0;
  constructor(readonly bytes: Uint8Array) {}

  get remaining(): number {
    return this.bytes.length - this.offset;
  }

  u8(): number {
    const b = this.bytes[this.offset];
    if (b === undefined) throw err('truncated');
    this.offset += 1;
    return b;
  }

  /** Bitcoin compact-size integer. */
  compactSize(): number {
    const first = this.u8();
    if (first < 0xfd) return first;
    let width: number;
    if (first === 0xfd) width = 2;
    else if (first === 0xfe) width = 4;
    else width = 8;
    let value = 0n;
    for (let i = 0; i < width; i++) value |= BigInt(this.u8()) << BigInt(8 * i);
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw err('length exceeds safe range');
    return Number(value);
  }

  take(length: number): Uint8Array {
    if (length > this.remaining) throw err('length exceeds input');
    const out = this.bytes.slice(this.offset, this.offset + length);
    this.offset += length;
    return out;
  }
}

/** Read one key/value map (ends at the 0x00 separator). */
function readMap(reader: Reader): PsbtKeyValue[] {
  const entries: PsbtKeyValue[] = [];
  const seen = new Set<string>();
  for (;;) {
    const keyLength = reader.compactSize();
    if (keyLength === 0) return entries;
    const key = reader.take(keyLength);
    const value = reader.take(reader.compactSize());
    const keyId = Array.from(key)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
    if (seen.has(keyId)) throw err('duplicate key within one map');
    seen.add(keyId);
    entries.push({ keyType: key[0]!, keyData: key.slice(1), value });
  }
}

/** Count of inputs/outputs in a (non-witness) unsigned transaction. */
function countTxInputsOutputs(tx: Uint8Array): { inputs: number; outputs: number } {
  const reader = new Reader(tx);
  reader.take(4); // version
  const inputs = reader.compactSize();
  if (inputs === 0) {
    // A zero here would be a segwit marker — the PSBT unsigned tx must not
    // carry witness data, so this is not a transaction we can count.
    throw err('unsigned transaction has zero inputs (or carries witness data)');
  }
  for (let i = 0; i < inputs; i++) {
    reader.take(32 + 4); // prevout
    reader.take(reader.compactSize()); // scriptSig (empty in a PSBT)
    reader.take(4); // sequence
  }
  const outputs = reader.compactSize();
  for (let i = 0; i < outputs; i++) {
    reader.take(8); // amount
    reader.take(reader.compactSize()); // scriptPubKey
  }
  reader.take(4); // locktime
  return { inputs, outputs };
}

export function parsePsbt(bytes: Uint8Array): ParsedPsbt {
  const reader = new Reader(bytes);
  for (const expected of MAGIC) {
    if (reader.u8() !== expected) throw err('bad magic');
  }
  const globalMap = readMap(reader);

  let unsignedTx: Uint8Array | null = null;
  let version = 0;
  for (const entry of globalMap) {
    if (entry.keyType === 0x00 && entry.keyData.length === 0) unsignedTx = entry.value;
    if (entry.keyType === 0xfb && entry.keyData.length === 0) {
      if (entry.value.length !== 4) throw err('bad version field');
      version =
        (entry.value[0]! | (entry.value[1]! << 8) | (entry.value[2]! << 16) | (entry.value[3]! << 24)) >>>
        0;
    }
  }
  if (unsignedTx === null) {
    // The device's signer relies on the global UNSIGNED_TX that only PSBT v0
    // carries; its absence means v2 (or not a PSBT at all).
    throw err('no global unsigned transaction — not a PSBT v0');
  }
  if (version !== 0) throw err(`unsupported PSBT version ${version}`);

  const counts = countTxInputsOutputs(unsignedTx);
  const inputs: PsbtKeyValue[][] = [];
  for (let i = 0; i < counts.inputs; i++) inputs.push(readMap(reader));
  const outputs: PsbtKeyValue[][] = [];
  for (let i = 0; i < counts.outputs; i++) outputs.push(readMap(reader));
  if (reader.remaining !== 0) throw err('trailing bytes after the output maps');

  return { unsignedTx, version, inputs, outputs };
}

export function inputEntries(
  psbt: ParsedPsbt,
  index: number,
  keyType: number,
): readonly PsbtKeyValue[] {
  return (psbt.inputs[index] ?? []).filter((e) => e.keyType === keyType);
}

export function inputHas(psbt: ParsedPsbt, index: number, keyType: number): boolean {
  return inputEntries(psbt, index, keyType).length > 0;
}
