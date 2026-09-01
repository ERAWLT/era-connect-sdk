import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha2';
import { keccak_256 } from '@noble/hashes/sha3';
import { equalBytes } from '../core/bytes';
import type { VerifyResult } from './result';
import { failed, verified } from './result';

export interface VerifyCosmosSignatureArgs {
  /** The exact SignDoc bytes the request carried. */
  readonly signData: Uint8Array;
  /**
   * Digest family: vanilla Cosmos zones hash with sha256; Ethermint chains
   * (Injective, Evmos, Dymension) with keccak256.
   */
  readonly digest: 'sha256' | 'keccak256';
  /** 64-byte compact signature from the reply. */
  readonly signature: Uint8Array;
  /** 33-byte compressed public key (from the reply, or derived from your linked xpub). */
  readonly publicKey: Uint8Array;
  /** Optional binding: the key you EXPECT (derived from the linked account). */
  readonly expectedPublicKey?: Uint8Array;
}

export function verifyCosmosSignature(args: VerifyCosmosSignatureArgs): VerifyResult {
  if (args.signature.length !== 64) return failed('signature must be 64 bytes (compact r||s)');
  if (args.publicKey.length !== 33) return failed('publicKey must be 33 bytes (compressed)');
  if (args.expectedPublicKey !== undefined && !equalBytes(args.publicKey, args.expectedPublicKey)) {
    return failed('the reply public key is not the linked account key');
  }
  const digest = args.digest === 'keccak256' ? keccak_256(args.signData) : sha256(args.signData);
  let ok: boolean;
  try {
    ok = secp256k1.verify(args.signature, digest, args.publicKey);
  } catch (e) {
    return failed(`Cosmos signature could not be checked: ${(e as Error).message}`);
  }
  return ok ? verified : failed('the signature does not belong to this account');
}
