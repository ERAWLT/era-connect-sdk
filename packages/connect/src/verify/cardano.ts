import { ed25519 } from '@noble/curves/ed25519';
import { blake2b } from '@noble/hashes/blake2b';
import { cardanoSoftDerivePath } from '../accounts/derive';
import type { CardanoWitness } from '../chains/cardano';
import { parseWitnessSet } from '../chains/cardano';
import { bytesToHex, equalBytes } from '../core/bytes';
import { parsePath } from '../registry/keypath';
import type { VerifyResult } from './result';
import { failed, verified } from './result';

export interface VerifyCardanoSignatureArgs {
  /** The exact bytes the request carried in `signData` (the full tx CBOR array). */
  readonly signData: Uint8Array;
  /** The reply's witness set (or already-parsed witnesses). */
  readonly witnessSet?: Uint8Array;
  readonly witnesses?: readonly CardanoWitness[];
  /**
   * Optional but STRONGLY recommended — binds the witnesses to YOUR wallet:
   * the linked account's key material plus the signing paths your request
   * carried. Without it the check only proves internal consistency of the
   * reply (any key could have produced a matching pair).
   */
  readonly account?: {
    /** From `accounts.cardano()`: the account xpub halves and its path. */
    readonly publicKey: Uint8Array;
    readonly chainCode: Uint8Array;
    readonly accountPath: string;
  };
  /** The unique signing paths of the request (utxos + certKeys), e.g. `m/1852'/1815'/0'/0/0`. */
  readonly signerPaths?: readonly string[];
}

/**
 * Recompute the digest the device signs — BLAKE2b-256 of the ENCODED FIRST
 * ELEMENT of the transaction CBOR array (the tx body) — and verify every
 * `[vkey, signature]` pair against it. With `account` + `signerPaths`, the
 * vkeys are additionally required to be exactly the soft-derived children of
 * YOUR linked account at the request's own paths.
 */
export function verifyCardanoSignature(args: VerifyCardanoSignatureArgs): VerifyResult {
  let witnesses: readonly CardanoWitness[];
  try {
    witnesses = args.witnesses ?? (args.witnessSet ? parseWitnessSet(args.witnessSet) : []);
  } catch (e) {
    return failed(`witness set is not readable: ${(e as Error).message}`);
  }
  if (witnesses.length === 0) return failed('no witnesses to verify');

  let digest: Uint8Array;
  try {
    digest = blake2b(firstArrayItemBytes(args.signData), { dkLen: 32 });
  } catch (e) {
    return failed(`signData is not a readable transaction array: ${(e as Error).message}`);
  }

  for (const witness of witnesses) {
    let ok: boolean;
    try {
      ok = ed25519.verify(witness.signature, digest, witness.vkey);
    } catch (e) {
      return failed(`Cardano signature could not be checked: ${(e as Error).message}`);
    }
    if (!ok) return failed('a witness signature does not verify against its own vkey');
  }

  if (args.account && args.signerPaths && args.signerPaths.length > 0) {
    const accountLevels = parsePath(args.account.accountPath);
    const expected = new Map<string, string>(); // vkey hex -> path
    for (const path of new Set(args.signerPaths)) {
      const levels = parsePath(path);
      if (
        levels.length !== accountLevels.length + 2 ||
        !accountLevels.every(
          (l, i) => levels[i]!.index === l.index && levels[i]!.hardened === l.hardened,
        ) ||
        levels.slice(accountLevels.length).some((l) => l.hardened)
      ) {
        return failed(
          `signer path ${path} does not extend the account path with two soft components`,
        );
      }
      const tail = levels.slice(accountLevels.length).map((l) => l.index);
      const vkey = cardanoSoftDerivePath(args.account.publicKey, args.account.chainCode, tail);
      expected.set(bytesToHex(vkey), path);
    }
    // Every requested path must have produced a witness…
    for (const [vkeyHex, path] of expected) {
      if (!witnesses.some((w) => bytesToHex(w.vkey) === vkeyHex)) {
        return failed(`no witness for the requested signer path ${path}`);
      }
    }
    // …and every witness must belong to a requested path (no foreign keys).
    for (const witness of witnesses) {
      if (!expected.has(bytesToHex(witness.vkey))) {
        return failed('the witness set carries a key your request did not ask for');
      }
    }
  }
  return verified;
}

// ---------------------------------------------------------------------------
// CBOR item walker: the encoded extent of the first element of a CBOR array.
// Supports definite AND indefinite lengths (wallet-produced tx CBOR may use
// either), with depth/size hardening.
// ---------------------------------------------------------------------------

export function firstArrayItemBytes(bytes: Uint8Array): Uint8Array {
  const top = bytes[0];
  if (top === undefined) throw new Error('empty input');
  const major = top >> 5;
  if (major !== 4) throw new Error('not a CBOR array');
  let start: number;
  if ((top & 0x1f) === 31) {
    start = 1; // indefinite array
  } else {
    const head = readHead(bytes, 0);
    if (head.value === 0n) throw new Error('transaction array is empty');
    start = head.next;
  }
  const end = skipItem(bytes, start, 0);
  return bytes.slice(start, end);
}

function readHead(bytes: Uint8Array, offset: number): { value: bigint; next: number } {
  const initial = bytes[offset];
  if (initial === undefined) throw new Error('truncated');
  const info = initial & 0x1f;
  if (info < 24) return { value: BigInt(info), next: offset + 1 };
  if (info === 31) return { value: -1n, next: offset + 1 }; // indefinite marker
  let width: number;
  if (info === 24) width = 1;
  else if (info === 25) width = 2;
  else if (info === 26) width = 4;
  else if (info === 27) width = 8;
  else throw new Error('reserved length encoding');
  let value = 0n;
  for (let i = 0; i < width; i++) {
    const b = bytes[offset + 1 + i];
    if (b === undefined) throw new Error('truncated');
    value = (value << 8n) | BigInt(b);
  }
  return { value, next: offset + 1 + width };
}

/** Returns the offset just past the item starting at `offset`. */
function skipItem(bytes: Uint8Array, offset: number, depth: number): number {
  if (depth > 32) throw new Error('nesting too deep');
  const initial = bytes[offset];
  if (initial === undefined) throw new Error('truncated');
  const major = initial >> 5;
  const head = readHead(bytes, offset);

  switch (major) {
    case 0:
    case 1:
      if (head.value === -1n) throw new Error('malformed integer');
      return head.next;
    case 2:
    case 3: {
      if (head.value === -1n) {
        // Indefinite string: chunks until 0xFF.
        let pos = head.next;
        while (bytes[pos] !== 0xff) {
          const chunk = readHead(bytes, pos);
          if (chunk.value < 0n) throw new Error('malformed chunk');
          pos = chunk.next + Number(chunk.value);
          if (pos > bytes.length) throw new Error('truncated string');
        }
        return pos + 1;
      }
      const end = head.next + Number(head.value);
      if (end > bytes.length) throw new Error('truncated string');
      return end;
    }
    case 4:
    case 5: {
      const perEntry = major === 5 ? 2 : 1;
      if (head.value === -1n) {
        let pos = head.next;
        while (bytes[pos] !== 0xff) {
          for (let i = 0; i < perEntry; i++) pos = skipItem(bytes, pos, depth + 1);
        }
        return pos + 1;
      }
      let pos = head.next;
      const count = Number(head.value) * perEntry;
      if (count > 1_000_000) throw new Error('container too large');
      for (let i = 0; i < count; i++) pos = skipItem(bytes, pos, depth + 1);
      return pos;
    }
    case 6:
      if (head.value === -1n) throw new Error('malformed tag');
      return skipItem(bytes, head.next, depth + 1);
    case 7:
      if ((initial & 0x1f) === 31) throw new Error('unexpected break');
      if ((initial & 0x1f) === 25) return offset + 3;
      if ((initial & 0x1f) === 26) return offset + 5;
      if ((initial & 0x1f) === 27) return offset + 9;
      return head.next;
    default:
      throw new Error('unreachable');
  }
}
