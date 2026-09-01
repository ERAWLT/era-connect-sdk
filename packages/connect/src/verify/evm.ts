import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';
import { EvmDataType, foldRecoveryId } from '../chains/evm';
import { bytesToHex, concatBytes, equalBytes, hexToBytes, utf8Encode } from '../core/bytes';
import type { VerifyResult } from './result';
import { failed, unverifiable, verified } from './result';

export interface VerifyEvmSignatureArgs {
  /** The exact bytes the request carried in `signData`. */
  readonly signData: Uint8Array;
  readonly dataType: EvmDataType;
  /** Raw `r || s || v` from the reply (65+ bytes; multi-byte legacy `v` handled). */
  readonly signature: Uint8Array;
  /** The signer address the request was built for. */
  readonly address: Uint8Array | `0x${string}`;
  /**
   * Optional: the signing payload re-derived from the transaction you are
   * ABOUT TO BROADCAST. Recovering against `signData` alone proves the device
   * signed something you asked for — this closes the second half: that it is
   * the transaction still in your hands (payloads can legitimately change
   * between build and send, e.g. a blockhash refresh in your own state).
   */
  readonly reEncodedSignData?: Uint8Array;
}

/** EIP-191: 0x19 || "Ethereum Signed Message:\n" || len(message). */
function personalSignDigest(message: Uint8Array): Uint8Array {
  const prefix = utf8Encode(`Ethereum Signed Message:\n${message.length}`);
  return keccak_256(concatBytes(new Uint8Array([0x19]), prefix, message));
}

/**
 * "Did the device sign exactly what I sent, with the key I expected?"
 * keccak digest + public-key recovery; the recovered address must equal the
 * request's. Run it before broadcasting.
 */
export function verifyEvmSignature(args: VerifyEvmSignatureArgs): VerifyResult {
  if (args.signature.length < 65) {
    return failed('signature is shorter than 65 bytes');
  }
  if (args.reEncodedSignData !== undefined && !equalBytes(args.reEncodedSignData, args.signData)) {
    return failed('the transaction to broadcast is not the one the device signed');
  }

  let digest: Uint8Array;
  switch (args.dataType) {
    case EvmDataType.transaction:
    case EvmDataType.typedTransaction:
      digest = keccak_256(args.signData);
      break;
    case EvmDataType.personalMessage:
      digest = personalSignDigest(args.signData);
      break;
    case EvmDataType.typedData:
      return unverifiable(
        'EIP-712: the digest is the hash of the structure, computed only on the device',
      );
    default:
      return failed(`unknown dataType ${args.dataType satisfies never}`);
  }

  let vBig = 0n;
  for (const b of args.signature.slice(64)) vBig = (vBig << 8n) | BigInt(b);
  const recoveryId = foldRecoveryId(vBig);
  if (recoveryId !== 0 && recoveryId !== 1) {
    return failed('implausible recovery value');
  }

  let recovered: Uint8Array;
  try {
    const point = secp256k1.Signature.fromCompact(args.signature.slice(0, 64))
      .addRecoveryBit(recoveryId)
      .recoverPublicKey(digest);
    recovered = keccak_256(point.toRawBytes(false).slice(1)).slice(12);
  } catch (e) {
    return failed(`signature could not be checked: ${(e as Error).message}`);
  }

  const expected = args.address instanceof Uint8Array ? args.address : hexToBytes(args.address);
  if (expected.length !== 20) {
    return failed(`expected address must be 20 bytes, got ${expected.length}`);
  }
  if (!equalBytes(recovered, expected)) {
    return failed(
      `the signature does not belong to this account (recovered 0x${bytesToHex(recovered)})`,
    );
  }
  return verified;
}
