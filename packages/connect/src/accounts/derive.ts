import { secp256k1 } from '@noble/curves/secp256k1';
import { blake2b } from '@noble/hashes/blake2b';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { sha256 } from '@noble/hashes/sha2';
import { keccak_256 } from '@noble/hashes/sha3';
import { base58, base58xrp, bech32, createBase58check } from '@scure/base';
import { HDKey } from '@scure/bip32';
import { encodeCashAddr } from '../chains/cashaddr';
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

function hash160(data: Uint8Array): Uint8Array {
  return ripemd160(sha256(data));
}

/** CashAddr P2PKH address (Bitcoin Cash) from a compressed public key. */
export function bchAddressFromPublicKey(
  publicKey33: Uint8Array,
  options?: { withPrefix?: boolean },
): string {
  return encodeCashAddr('p2pkh', hash160(publicKey33), { withPrefix: options?.withPrefix });
}

/** P2WPKH (witness v0) bech32 address. */
export function btcP2wpkhAddressFromPublicKey(
  publicKey33: Uint8Array,
  hrp: 'bc' | 'tb' = 'bc',
): string {
  return bech32.encode(hrp, [0, ...bech32.toWords(hash160(publicKey33))]);
}

/** Legacy P2PKH base58check address (`1...`). */
export function btcP2pkhAddressFromPublicKey(publicKey33: Uint8Array, testnet = false): string {
  return base58check.encode(
    concatBytes(new Uint8Array([testnet ? 0x6f : 0x00]), hash160(publicKey33)),
  );
}

/** Nested segwit (P2SH-P2WPKH) base58check address (`3...`). */
export function btcNestedSegwitAddressFromPublicKey(
  publicKey33: Uint8Array,
  testnet = false,
): string {
  const redeemScript = concatBytes(new Uint8Array([0x00, 0x14]), hash160(publicKey33));
  return base58check.encode(
    concatBytes(new Uint8Array([testnet ? 0xc4 : 0x05]), hash160(redeemScript)),
  );
}

/**
 * Cosmos bech32 address: plain bech32 of the 20-byte hash160, with NO
 * witness-version prefix (that is a segwit thing, not a Cosmos one). Every
 * zone carries its own HRP over the same key, so `prefix` is the caller's.
 */
export function cosmosAddressFromPublicKey(publicKey33: Uint8Array, prefix: string): string {
  return bech32.encode(prefix, bech32.toWords(hash160(publicKey33)));
}

/**
 * XRP classic address (`r...`): base58check over `0x00 || hash160(pubkey)`,
 * with Bitcoin's double-SHA-256 check but XRPL's own base58 dictionary.
 * `createBase58check` is hard-wired to the Bitcoin alphabet, so the four
 * checksum bytes are appended explicitly here.
 */
export function xrpAddressFromPublicKey(publicKey: Uint8Array): string {
  const payload = concatBytes(new Uint8Array([0x00]), hash160(publicKey));
  return base58xrp.encode(concatBytes(payload, sha256(sha256(payload)).slice(0, 4)));
}

/** Tron base58check address (0x41-prefixed keccak hash). */
export function tronAddressFromPublicKey(publicKey33: Uint8Array): string {
  const hash = keccak_256(uncompressed(publicKey33).slice(1));
  return base58check.encode(concatBytes(new Uint8Array([0x41]), hash.slice(12)));
}

/** `0x` Sui address: BLAKE2b-256 of the scheme flag (0x00 = Ed25519) plus the public key. */
export function suiAddressFromPublicKey(publicKey32: Uint8Array): string {
  const digest = blake2b(concatBytes(new Uint8Array([0x00]), publicKey32), { dkLen: 32 });
  return `0x${bytesToHex(digest)}`;
}

/** A Solana address IS the Ed25519 public key, base58. */
export function solanaAddressFromPublicKey(publicKey32: Uint8Array): string {
  return base58.encode(publicKey32);
}

const XPUB_VERSION = 0x0488b21e;
const ZPUB_VERSION = 0x04b24746; // SLIP-132, BIP-84 P2WPKH
const TPUB_VERSION = 0x043587cf; // SLIP-132, testnet counterpart of xpub
const VPUB_VERSION = 0x045f1cf6; // SLIP-132, BIP-84 P2WPKH testnet

/** BIP-32 extended public key serialization. */
export function serializeExtendedPublicKey(args: {
  version?: number;
  depth: number;
  parentFingerprint: number;
  childNumber: number;
  chainCode: Uint8Array;
  publicKey: Uint8Array;
}): string {
  const {
    version = XPUB_VERSION,
    depth,
    parentFingerprint,
    childNumber,
    chainCode,
    publicKey,
  } = args;
  if (chainCode.length !== 32 || publicKey.length !== 33) {
    throw new EraSdkError(
      'invalid-props',
      'extended key needs a 32-byte chain code and 33-byte key',
    );
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

export { TPUB_VERSION, VPUB_VERSION, XPUB_VERSION, ZPUB_VERSION };

// ---------------------------------------------------------------------------
// Cardano (BIP32-Ed25519 / CIP-3 "V2") soft public derivation
// ---------------------------------------------------------------------------

import { ed25519 } from '@noble/curves/ed25519';
import { hmac } from '@noble/hashes/hmac';
import { sha512 } from '@noble/hashes/sha2';

function u32le(value: number): Uint8Array {
  return new Uint8Array([
    value & 0xff,
    (value >> 8) & 0xff,
    (value >> 16) & 0xff,
    (value >> 24) & 0xff,
  ]);
}

function leBytesToBigint(bytes: Uint8Array): bigint {
  let out = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) out = (out << 8n) | BigInt(bytes[i]!);
  return out;
}

/**
 * Public (soft) child of a BIP32-Ed25519 extended public key — the scheme
 * Cardano wallets share account xpubs under (CIP-3/V2):
 *
 *   Z       = HMAC-SHA512(chainCode, 0x02 || A || le32(index))
 *   childA  = A + [8 * ZL[0..28]] * B
 *   childCC = HMAC-SHA512(chainCode, 0x03 || A || le32(index))[32..]
 *
 * Only non-hardened indices are derivable publicly, which is exactly what the
 * role/index tail of a CIP-1852 path uses.
 */
export function cardanoSoftDeriveChild(
  publicKey: Uint8Array,
  chainCode: Uint8Array,
  index: number,
): { publicKey: Uint8Array; chainCode: Uint8Array } {
  if (publicKey.length !== 32 || chainCode.length !== 32) {
    throw new EraSdkError('invalid-props', 'Cardano derivation needs a 32-byte key and chain code');
  }
  if (!Number.isSafeInteger(index) || index < 0 || index >= 0x80000000) {
    throw new EraSdkError('invalid-props', 'Cardano public derivation is soft-index only');
  }
  const z = hmac(sha512, chainCode, concatBytes(new Uint8Array([0x02]), publicKey, u32le(index)));
  const cc = hmac(
    sha512,
    chainCode,
    concatBytes(new Uint8Array([0x03]), publicKey, u32le(index)),
  ).slice(32);
  const scalar = 8n * leBytesToBigint(z.slice(0, 28));
  const parent = ed25519.ExtendedPoint.fromHex(bytesToHex(publicKey));
  const child = scalar === 0n ? parent : parent.add(ed25519.ExtendedPoint.BASE.multiply(scalar));
  return { publicKey: child.toRawBytes(), chainCode: cc };
}

/** Soft-derive along several indices (e.g. role, then address index). */
export function cardanoSoftDerivePath(
  publicKey: Uint8Array,
  chainCode: Uint8Array,
  indices: readonly number[],
): Uint8Array {
  let node = { publicKey, chainCode };
  for (const index of indices) {
    node = cardanoSoftDeriveChild(node.publicKey, node.chainCode, index);
  }
  return node.publicKey;
}
