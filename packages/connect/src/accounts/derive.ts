import { secp256k1 } from '@noble/curves/secp256k1';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { sha256 } from '@noble/hashes/sha2';
import { keccak_256 } from '@noble/hashes/sha3';
import { base58, bech32, createBase58check } from '@scure/base';
import { HDKey } from '@scure/bip32';
import { bytesToHex, concatBytes, u32be } from '../core/bytes';
import { EraSdkError } from '../core/errors';

const base58check = createBase58check(sha256);

/** Non-hardened BIP-32 child public key from an account-level (publicKey, chainCode). */
export function derivePublicKey(
  publicKey: Uint8Array,
  chainCode: Uint8Array,
  change: number,
  index: number,
): Uint8Array {
  const node = new HDKey({ publicKey, chainCode });
  const child = node.deriveChild(change).deriveChild(index);
  if (!child.publicKey) {
    throw new EraSdkError('invalid-props', 'child derivation produced no public key');
  }
  return child.publicKey;
}

function uncompressed(publicKey33: Uint8Array): Uint8Array {
  return secp256k1.ProjectivePoint.fromHex(publicKey33).toRawBytes(false);
}

/** EIP-55 checksummed address from a compressed secp256k1 public key. */
export function evmAddressFromPublicKey(publicKey33: Uint8Array): `0x${string}` {
  const hash = keccak_256(uncompressed(publicKey33).slice(1));
  const addr = bytesToHex(hash.slice(12));
  const check = keccak_256(new Uint8Array([...addr].map((c) => c.charCodeAt(0))));
  let out = '';
  for (let i = 0; i < addr.length; i++) {
    const nibble = i % 2 === 0 ? check[i >> 1]! >> 4 : check[i >> 1]! & 0x0f;
    out += nibble >= 8 ? addr[i]!.toUpperCase() : addr[i]!;
  }
  return `0x${out}`;
}

/** P2WPKH (witness v0) bech32 address. */
export function btcP2wpkhAddressFromPublicKey(
  publicKey33: Uint8Array,
  hrp: 'bc' | 'tb' = 'bc',
): string {
  const program = ripemd160(sha256(publicKey33));
  return bech32.encode(hrp, [0, ...bech32.toWords(program)]);
}

/** Tron base58check address (0x41-prefixed keccak hash). */
export function tronAddressFromPublicKey(publicKey33: Uint8Array): string {
  const hash = keccak_256(uncompressed(publicKey33).slice(1));
  return base58check.encode(concatBytes(new Uint8Array([0x41]), hash.slice(12)));
}

/** A Solana address IS the Ed25519 public key, base58. */
export function solanaAddressFromPublicKey(publicKey32: Uint8Array): string {
  return base58.encode(publicKey32);
}

const XPUB_VERSION = 0x0488b21e;
const ZPUB_VERSION = 0x04b24746; // SLIP-132, BIP-84 P2WPKH

/** BIP-32 extended public key serialization. */
export function serializeExtendedPublicKey(args: {
  version?: number;
  depth: number;
  parentFingerprint: number;
  childNumber: number;
  chainCode: Uint8Array;
  publicKey: Uint8Array;
}): string {
  const { version = XPUB_VERSION, depth, parentFingerprint, childNumber, chainCode, publicKey } =
    args;
  if (chainCode.length !== 32 || publicKey.length !== 33) {
    throw new EraSdkError('invalid-props', 'extended key needs a 32-byte chain code and 33-byte key');
  }
  return base58check.encode(
    concatBytes(
      u32be(version),
      new Uint8Array([depth & 0xff]),
      u32be(parentFingerprint),
      u32be(childNumber),
      chainCode,
      publicKey,
    ),
  );
}

export { XPUB_VERSION, ZPUB_VERSION };
