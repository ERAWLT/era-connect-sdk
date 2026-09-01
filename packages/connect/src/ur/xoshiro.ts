/**
 * Xoshiro256** seeded from a 32-byte digest, with the exact
 * `(x >>> 11) * 2^-53` double conversion the BC-UR fountain code uses.
 *
 * The draw sequence IS the wire protocol: the device runs the same PRNG over
 * the same seed to derive which source fragments a fountain frame covers.
 */

const MASK64 = (1n << 64n) - 1n;

function rotl(x: bigint, k: bigint): bigint {
  return ((x << k) | (x >> (64n - k))) & MASK64;
}

export class Xoshiro256ss {
  private s0: bigint;
  private s1: bigint;
  private s2: bigint;
  private s3: bigint;

  /** Seed from a 32-byte digest split into four big-endian u64 words. */
  constructor(digest: Uint8Array) {
    if (digest.length !== 32) throw new Error('xoshiro seed must be 32 bytes');
    const word = (offset: number): bigint => {
      let v = 0n;
      for (let i = 0; i < 8; i++) v = (v << 8n) | BigInt(digest[offset + i]!);
      return v;
    };
    this.s0 = word(0);
    this.s1 = word(8);
    this.s2 = word(16);
    this.s3 = word(24);
    if ((this.s0 | this.s1 | this.s2 | this.s3) === 0n) {
      throw new Error('xoshiro seed must not be all zeros');
    }
  }

  nextRaw64(): bigint {
    const result = (rotl((this.s1 * 5n) & MASK64, 7n) * 9n) & MASK64;
    const t = (this.s1 << 17n) & MASK64;
    this.s2 ^= this.s0;
    this.s3 ^= this.s1;
    this.s1 ^= this.s2;
    this.s0 ^= this.s3;
    this.s2 ^= t;
    this.s3 = rotl(this.s3, 45n);
    return result;
  }

  /** Uniform double in [0, 1): top 53 bits of the raw draw. Exact — no precision loss. */
  nextDouble(): number {
    return Number(this.nextRaw64() >> 11n) * 2 ** -53;
  }
}
