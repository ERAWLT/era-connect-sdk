import { ed25519 } from '@noble/curves/ed25519';
import { suiIntentDigest } from '../chains/sui';
import { equalBytes } from '../core/bytes';
import type { VerifyResult } from './result';
import { failed, verified } from './result';

export interface VerifySuiSignatureArgs {
  /** The intent message the request carried (or pass `messageHash` for the hash variant). */
  readonly intentMessage?: Uint8Array;
  readonly messageHash?: Uint8Array;
  /** 64-byte Ed25519 signature from the reply. */
  readonly signature: Uint8Array;
  /** The signer key the reply carried. */
  readonly publicKey: Uint8Array;
  /** The linked account's key (`accounts.sui()[i].publicKey`) — binds the reply to YOUR wallet. */
  readonly expectedPublicKey?: Uint8Array;
}

/** BLAKE2b-256 of the intent message (or the given hash) + Ed25519 verification. */
export function verifySuiSignature(args: VerifySuiSignatureArgs): VerifyResult {
  let digest: Uint8Array;
  if (args.messageHash !== undefined) {
    if (args.messageHash.length !== 32) return failed('messageHash must be 32 bytes');
    digest = args.messageHash;
  } else if (args.intentMessage !== undefined) {
    digest = suiIntentDigest(args.intentMessage);
  } else {
    return failed('provide intentMessage or messageHash');
  }
  if (args.expectedPublicKey !== undefined && !equalBytes(args.publicKey, args.expectedPublicKey)) {
    return failed('the reply public key is not the linked account key');
  }
  let ok: boolean;
  try {
    ok = ed25519.verify(args.signature, digest, args.publicKey);
  } catch (e) {
    return failed(`Sui signature could not be checked: ${(e as Error).message}`);
  }
  return ok ? verified : failed('the signature does not belong to this account');
}
