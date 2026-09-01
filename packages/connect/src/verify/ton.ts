import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha2';
import { TonDataType } from '../chains/ton';
import { concatBytes, utf8Encode } from '../core/bytes';
import type { VerifyResult } from './result';
import { failed, verified } from './result';
import { bocRootHash } from './ton-boc';

export interface VerifyTonSignatureArgs {
  /** The exact bytes the request carried in `signData`. */
  readonly signData: Uint8Array;
  readonly dataType: TonDataType;
  /** 64-byte Ed25519 signature from the reply. */
  readonly signature: Uint8Array;
  /** The 32-byte signer public key from linking (`accounts.ton()`). */
  readonly publicKey: Uint8Array;
}

/**
 * Recompute the exact digest the device signs — the BoC ROOT CELL's
 * representation hash for a transaction, or the TON Connect proof digest
 * `sha256(0xFFFF || "ton-connect" || sha256(payload))` — and verify the
 * Ed25519 signature against the linked key.
 */
export function verifyTonSignature(args: VerifyTonSignatureArgs): VerifyResult {
  if (args.signature.length !== 64) return failed('signature must be 64 bytes');
  if (args.publicKey.length !== 32) return failed('public key must be 32 bytes');

  let digest: Uint8Array;
  if (args.dataType === TonDataType.tonProof) {
    digest = sha256(
      concatBytes(new Uint8Array([0xff, 0xff]), utf8Encode('ton-connect'), sha256(args.signData)),
    );
  } else if (args.dataType === TonDataType.transaction) {
    try {
      digest = bocRootHash(args.signData);
    } catch (e) {
      return failed(`signData is not a readable BoC: ${(e as Error).message}`);
    }
  } else {
    return failed(`unknown dataType ${args.dataType satisfies never}`);
  }

  let ok: boolean;
  try {
    ok = ed25519.verify(args.signature, digest, args.publicKey);
  } catch (e) {
    return failed(`TON signature could not be checked: ${(e as Error).message}`);
  }
  return ok ? verified : failed('the signature does not belong to this account');
}
