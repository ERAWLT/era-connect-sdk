/**
 * TEST-ONLY Cardano Icarus (CIP-3 / BIP32-Ed25519 "V2") PRIVATE-side
 * implementation: master key from entropy, hardened/soft private derivation,
 * extended signing. It exists to cross-validate the SDK's PUBLIC soft
 * derivation and digest against an independent private-side computation
 * (and against the firmware corpus, which signs from the same scheme).
 */
import { ed25519 } from '@noble/curves/ed25519';
import { hmac } from '@noble/hashes/hmac';
import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { sha512 } from '@noble/hashes/sha2';

export interface XPrv {
  kL: Uint8Array; // 32-byte scalar (little-endian)
  kR: Uint8Array; // 32-byte nonce seed
  chainCode: Uint8Array;
}

const N = ed25519.CURVE.n;

function leToBigint(bytes: Uint8Array): bigint {
  let out = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) out = (out << 8n) | BigInt(bytes[i]!);
  return out;
}

function bigintToLe(value: bigint, length: number): Uint8Array {
  const out = new Uint8Array(length);
  let v = value;
  for (let i = 0; i < length; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function u32le(value: number): Uint8Array {
  return new Uint8Array([
    value & 0xff,
    (value >> 8) & 0xff,
    (value >> 16) & 0xff,
    (value >> 24) & 0xff,
  ]);
}

/** 32-byte LE addition a + b, final carry dropped (cardano-crypto semantics). */
function addLe(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(32);
  let carry = 0;
  for (let i = 0; i < 32; i++) {
    const sum = (a[i] ?? 0) + (b[i] ?? 0) + carry;
    out[i] = sum & 0xff;
    carry = sum >> 8;
  }
  return out;
}

/** kL + 8 * ZL[0..28], 32-byte LE, carry dropped. */
function add28Mul8(kL: Uint8Array, zL: Uint8Array): Uint8Array {
  const mul = bigintToLe(8n * leToBigint(zL.slice(0, 28)), 32);
  return addLe(kL, mul);
}

export function publicKeyOf(kL: Uint8Array): Uint8Array {
  const scalar = leToBigint(kL) % N;
  return ed25519.ExtendedPoint.BASE.multiply(scalar).toRawBytes();
}

/** Icarus master key: PBKDF2-HMAC-SHA512(pass="", salt=entropy, 4096, 96) + V2 clamp. */
export function icarusMasterFromEntropy(entropy: Uint8Array): XPrv {
  const out = pbkdf2(sha512, new Uint8Array(0), entropy, { c: 4096, dkLen: 96 });
  const kL = out.slice(0, 32);
  kL[0]! &= 0b1111_1000;
  kL[31]! &= 0b0001_1111;
  kL[31]! |= 0b0100_0000;
  return { kL, kR: out.slice(32, 64), chainCode: out.slice(64, 96) };
}

export function deriveChild(parent: XPrv, index: number, hardened: boolean): XPrv {
  const i = hardened ? index + 0x80000000 : index;
  let z: Uint8Array;
  let cc: Uint8Array;
  if (hardened) {
    z = hmac(
      sha512,
      parent.chainCode,
      new Uint8Array([0x00, ...parent.kL, ...parent.kR, ...u32le(i)]),
    );
    cc = hmac(
      sha512,
      parent.chainCode,
      new Uint8Array([0x01, ...parent.kL, ...parent.kR, ...u32le(i)]),
    ).slice(32);
  } else {
    const a = publicKeyOf(parent.kL);
    z = hmac(sha512, parent.chainCode, new Uint8Array([0x02, ...a, ...u32le(i)]));
    cc = hmac(sha512, parent.chainCode, new Uint8Array([0x03, ...a, ...u32le(i)])).slice(32);
  }
  return {
    kL: add28Mul8(parent.kL, z.slice(0, 32)),
    kR: addLe(parent.kR, z.slice(32, 64)),
    chainCode: cc,
  };
}

export function derivePath(root: XPrv, levels: { index: number; hardened: boolean }[]): XPrv {
  let node = root;
  for (const level of levels) node = deriveChild(node, level.index, level.hardened);
  return node;
}

/** Cardano ed25519-extended signing of a message (here: the 32-byte tx hash). */
export function extendedSign(key: XPrv, message: Uint8Array): Uint8Array {
  const a = publicKeyOf(key.kL);
  const nonce = leToBigint(sha512(new Uint8Array([...key.kR, ...message]))) % N;
  const rPoint = ed25519.ExtendedPoint.BASE.multiply(nonce === 0n ? 1n : nonce);
  const rBytes = rPoint.toRawBytes();
  const hram = leToBigint(sha512(new Uint8Array([...rBytes, ...a, ...message]))) % N;
  const s = (nonce + hram * (leToBigint(key.kL) % N)) % N;
  return new Uint8Array([...rBytes, ...bigintToLe(s, 32)]);
}
