import { ed25519 } from '@noble/curves/ed25519';
import { equalBytes } from '../core/bytes';
import type { VerifyResult } from './result';
import { failed, verified } from './result';

export interface VerifySolanaSignatureArgs {
  /** The exact bytes the request carried in `signData` (the compiled message). */
  readonly signData: Uint8Array;
  /** 64-byte Ed25519 signature from the reply. */
  readonly signature: Uint8Array;
  /** The 32-byte signer public key the request was built for. */
  readonly publicKey: Uint8Array;
  /**
   * Optional: the message bytes you are ABOUT TO BROADCAST. Matters most on
   * Solana — a blockhash refresh between build and send makes "what was
   * signed" and "what will be sent" two different objects that must agree.
   */
  readonly broadcastMessageBytes?: Uint8Array;
}

export function verifySolanaSignature(args: VerifySolanaSignatureArgs): VerifyResult {
  if (
    args.broadcastMessageBytes !== undefined &&
    !equalBytes(args.broadcastMessageBytes, args.signData)
  ) {
    return failed('the message to broadcast is not the one the device signed');
  }
  let ok: boolean;
  try {
    ok = ed25519.verify(args.signature, args.signData, args.publicKey);
  } catch (e) {
    return failed(`Solana signature could not be checked: ${(e as Error).message}`);
  }
  return ok ? verified : failed('the signature does not belong to this account');
}
