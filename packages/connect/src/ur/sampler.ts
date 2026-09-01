import { sha256 } from '@noble/hashes/sha2';
import { concatBytes, u32be } from '../core/bytes';
import { UrLimits } from './limits';
import { Xoshiro256ss } from './xoshiro';

/**
 * Which source fragments the fountain frame `seqNum` of `seqLength` covers.
 *
 * For `seqNum <= seqLength` the frame is the source fragment itself. Above
 * that, the BC-UR fountain sampler runs: seed = sha256(seqNum || checksum)
 * (both big-endian u32), Xoshiro256** drives an alias-method degree chooser
 * over `1/(i+1)` weights, then a full draw-without-replacement permutation of
 * which the first `degree` indexes are taken.
 *
 * Every draw below happens in the exact order of the reference
 * implementation. The draw order IS the wire protocol — a different (even
 * "equivalent") shuffle makes the device's fountain frames undecodable.
 */
export function chooseFragmentIndexes(
  seqNum: number,
  seqLength: number,
  checksum: number,
): number[] {
  if (seqLength < 1 || seqLength > UrLimits.maxFragmentCount) {
    throw new RangeError(
      `seqLength ${seqLength} outside 1..${UrLimits.maxFragmentCount}; ` +
        'cannot build fountain indexes for a UR this large',
    );
  }
  if (seqNum <= seqLength) return [seqNum - 1];

  const digest = sha256(concatBytes(u32be(seqNum), u32be(checksum)));
  const rng = new Xoshiro256ss(digest);

  // Alias-method table over degree weights 1/(i+1).
  const scaled = new Array<number>(seqLength);
  let sum = 0;
  for (let i = 0; i < seqLength; i++) sum += 1 / (i + 1);
  for (let i = 0; i < seqLength; i++) scaled[i] = (1 / (i + 1)) * seqLength / sum;

  const prob = new Array<number>(seqLength).fill(0);
  const alias = new Array<number>(seqLength).fill(0);
  const small: number[] = [];
  const large: number[] = [];
  for (let i = seqLength - 1; i >= 0; i--) {
    (scaled[i]! < 1 ? small : large).push(i);
  }
  while (small.length > 0 && large.length > 0) {
    const less = small.pop()!;
    const more = large.pop()!;
    prob[less] = scaled[less]!;
    alias[less] = more;
    scaled[more] = scaled[more]! + scaled[less]! - 1;
    (scaled[more]! < 1 ? small : large).push(more);
  }
  while (large.length > 0) prob[large.pop()!] = 1;
  while (small.length > 0) prob[small.pop()!] = 1;

  const c = Math.floor(rng.nextDouble() * prob.length);
  const sample = rng.nextDouble() < prob[c]! ? c : alias[c]!;
  const degree = sample + 1;

  // Full permutation by draw-without-replacement; take the first `degree`.
  const remaining: number[] = [];
  for (let i = 0; i < seqLength; i++) remaining.push(i);
  const permutation: number[] = [];
  while (remaining.length > 0) {
    const index = Math.floor(rng.nextDouble() * remaining.length);
    permutation.push(remaining.splice(index, 1)[0]!);
  }
  return permutation.slice(0, degree);
}
