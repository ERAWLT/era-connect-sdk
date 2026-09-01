import { equalBytes } from '../core/bytes';
import { EraSdkError } from '../core/errors';
import type { ParsedPsbt } from './psbt-reader';
import { inputEntries, inputHas, parsePsbt, PsbtInputType } from './psbt-reader';
import type { VerifyResult } from './result';
import { failed, verified } from './result';

export interface VerifySignedPsbtArgs {
  /** The PSBT you sent to the device. */
  readonly sentPsbt: Uint8Array;
  /** The PSBT the device returned. */
  readonly signedPsbt: Uint8Array;
  /**
   * true (default) on flows where every input is yours (a plain send): a
   * reply that signed only part of the transaction is refused here with a
   * reason instead of failing later inside a finalizer. Set false for dApp
   * `signPsbt` hand-backs, where a PSBT legitimately carries inputs you
   * cannot sign.
   */
  readonly requireEveryInputSigned?: boolean;
}

/**
 * The `crypto-psbt` reply carries NO request id — this comparison IS the
 * anti-replay binding for Bitcoin. It is not optional.
 *
 * The unsigned transaction is compared byte for byte, which pins the input
 * set and order, the outputs, their amounts, the version and the locktime in
 * one shot — and therefore the txid. The device only ADDS per-input
 * signature fields, so a legitimate reply always matches.
 */
export function verifySignedPsbt(args: VerifySignedPsbtArgs): VerifyResult {
  let sent: ParsedPsbt;
  let signed: ParsedPsbt;
  try {
    sent = parsePsbt(args.sentPsbt);
  } catch (e) {
    return failed(`the PSBT we sent is not readable: ${message(e)}`);
  }
  try {
    signed = parsePsbt(args.signedPsbt);
  } catch (e) {
    return failed(`the PSBT the device returned is not readable: ${message(e)}`);
  }

  if (!equalBytes(sent.unsignedTx, signed.unsignedTx)) {
    return failed('the returned PSBT is a different transaction from the one approved');
  }

  // A finalized field carries the COMPLETE scriptSig/witness that will be
  // broadcast, and the unsigned-tx comparison above does not cover it (it
  // lives per input, the unsigned tx in the global map). An input that comes
  // back finalized must have been SENT that way, with byte-identical
  // values — the device echoes these fields, it never authors them.
  const finalizedTypes = [PsbtInputType.finalScriptSig, PsbtInputType.finalScriptWitness];
  for (let i = 0; i < signed.inputs.length; i++) {
    for (const type of finalizedTypes) {
      if (!inputHas(signed, i, type)) continue;
      if (!inputHas(sent, i, type)) {
        return failed(
          `input ${i} came back finalized (type 0x${type.toString(16)}) and was not sent that way — the script it would broadcast is not ours`,
        );
      }
      const a = inputEntries(sent, i, type);
      const b = inputEntries(signed, i, type);
      if (a.length !== b.length || !a.every((entry, k) => equalBytes(entry.value, b[k]!.value))) {
        return failed(
          `input ${i} came back with a different finalized script than the one we sent`,
        );
      }
    }
  }

  const isSigned = (i: number): boolean =>
    inputHas(signed, i, PsbtInputType.partialSig) ||
    inputHas(signed, i, PsbtInputType.taprootKeySpendSignature) ||
    inputHas(signed, i, PsbtInputType.taprootScriptSpendSignature);

  const indexes = signed.inputs.map((_, i) => i);
  if (args.requireEveryInputSigned ?? true) {
    if (!indexes.every(isSigned)) {
      return failed('the device signed only part of the transaction');
    }
  } else if (!indexes.some(isSigned)) {
    return failed('the returned PSBT carries no signature');
  }
  return verified;
}

export interface VerifyBtcMessageHeaderArgs {
  /** The address the request asked the device to sign with. */
  readonly address: string;
  /** The raw 65-byte BIP-137 signature. */
  readonly signature: Uint8Array;
}

/**
 * BIP-137: the recovery header names the address type a verifier derives
 * before comparing. A header of the wrong range produces a signature that
 * LOOKS fine (65 bytes, valid base64) but fails every verifier downstream —
 * this check is the only place that difference is visible.
 */
export function verifyBtcMessageHeader(args: VerifyBtcMessageHeaderArgs): VerifyResult {
  if (args.signature.length === 0) {
    return failed('empty signature');
  }
  const header = args.signature[0]!;
  const range = headerRangeFor(args.address);
  if (range === null) {
    return {
      ok: true,
      checked: false,
      reason: 'address kind has no BIP-137 header range to check against',
    };
  }
  if (header >= range.low && header <= range.high) return verified;
  return failed(
    `recovery header ${header} does not match a ${range.label} address ` +
      `(BIP-137 expects ${range.low}..${range.high}); this signature would not verify against the address it was asked to sign for`,
  );
}

interface HeaderRange {
  readonly low: number;
  readonly high: number;
  readonly label: string;
}

function headerRangeFor(address: string): HeaderRange | null {
  const a = address.toLowerCase();
  if (a.startsWith('bc1q') || a.startsWith('tb1q') || a.startsWith('bcrt1q')) {
    return { low: 39, high: 42, label: 'native segwit (P2WPKH)' };
  }
  if (a.startsWith('bc1p') || a.startsWith('tb1p') || a.startsWith('bcrt1p')) {
    return null; // Taproot: BIP-137 does not cover it (BIP-322 is the scheme).
  }
  // Base58 kinds matched on SHAPE, not first character alone — a guard that
  // invents a range for a string it does not understand is worse than one
  // that declines to judge.
  if (looksBase58(address)) {
    if (address.startsWith('3') || address.startsWith('2')) {
      return { low: 35, high: 38, label: 'P2SH (nested segwit)' };
    }
    if (address.startsWith('1') || address.startsWith('m') || address.startsWith('n')) {
      // Both the uncompressed and compressed P2PKH ranges — which one is
      // right depends on the key the device used, which we do not know.
      return { low: 27, high: 34, label: 'legacy P2PKH' };
    }
  }
  return null;
}

function looksBase58(address: string): boolean {
  return (
    address.length >= 26 && address.length <= 35 && /^[1-9A-HJ-NP-Za-km-z]+$/.test(address)
  );
}

function message(e: unknown): string {
  return e instanceof EraSdkError || e instanceof Error ? e.message : String(e);
}
