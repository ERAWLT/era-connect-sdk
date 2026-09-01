import {
  URDecoder as NgraveDecoder,
  UREncoder as NgraveEncoder,
  UR as NgraveUr,
} from '@ngraveio/bc-ur';
import { describe, expect, it } from 'vitest';
import { bytesToHex } from '../src/core/bytes';
import { UrDecoder } from '../src/ur/decoder';
import { UrFountainEncoder } from '../src/ur/encoder';
import { Ur } from '../src/ur/ur';

/**
 * Differential round-trips against @ngraveio/bc-ur@1.1.13 — the implementation
 * the installed base (MetaMask Mobile, Rabby, Keystone SDK) actually runs.
 * Node-only devDependency; Buffer is fine here.
 */

/** Deterministic xorshift so failures replay from the case number. */
function makePrng(seed: number) {
  let s = seed >>> 0 || 1;
  return () => {
    s ^= s << 13;
    s ^= s >>> 17;
    s ^= s << 5;
    return (s >>> 0) / 0x100000000;
  };
}

function randomPayload(rnd: () => number, length: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) out[i] = Math.floor(rnd() * 256);
  return out;
}

const CASES = 120;

describe('differential vs @ngraveio/bc-ur', () => {
  it('our frames decode in their decoder', () => {
    for (let c = 0; c < CASES; c++) {
      const rnd = makePrng(c + 1);
      const length = 1 + Math.floor(rnd() * 2000);
      const fragLen = 10 + Math.floor(rnd() * 190);
      const payload = randomPayload(rnd, length);

      const encoder = new UrFountainEncoder(new Ur('bytes', payload), fragLen, 10);
      const theirDecoder = new NgraveDecoder();
      const budget = encoder.fragmentCount * 3 + 3;
      for (let i = 0; i < budget && !theirDecoder.isComplete(); i++) {
        theirDecoder.receivePart(encoder.nextPart());
      }
      expect(theirDecoder.isSuccess(), `case ${c}: len=${length} frag=${fragLen}`).toBe(true);
      const result = theirDecoder.resultUR();
      expect(result.type).toBe('bytes');
      expect(result.cbor.toString('hex')).toBe(bytesToHex(payload));
    }
  });

  it('their frames decode in our decoder', () => {
    for (let c = 0; c < CASES; c++) {
      const rnd = makePrng(c + 1000);
      const length = 1 + Math.floor(rnd() * 2000);
      const fragLen = 10 + Math.floor(rnd() * 190);
      const payload = randomPayload(rnd, length);

      const theirEncoder = new NgraveEncoder(
        new NgraveUr(Buffer.from(payload), 'bytes'),
        fragLen,
        0,
        10,
      );
      const ourDecoder = new UrDecoder();
      let complete = false;
      const budget = theirEncoder.fragmentsLength * 3 + 3;
      for (let i = 0; i < budget && !complete; i++) {
        complete = ourDecoder.receivePart(theirEncoder.nextPart());
      }
      expect(complete, `case ${c}: len=${length} frag=${fragLen}`).toBe(true);
      expect(bytesToHex(ourDecoder.result().cbor)).toBe(bytesToHex(payload));
    }
  });

  it('frame strings are identical for identical (payload, fragLen, seqNum)', () => {
    for (let c = 0; c < 40; c++) {
      const rnd = makePrng(c + 5000);
      const length = 50 + Math.floor(rnd() * 1000);
      const fragLen = 10 + Math.floor(rnd() * 90);
      const payload = randomPayload(rnd, length);

      const ours = new UrFountainEncoder(new Ur('bytes', payload), fragLen, 10);
      const theirs = new NgraveEncoder(new NgraveUr(Buffer.from(payload), 'bytes'), fragLen, 0, 10);
      if (ours.isSinglePart) {
        expect(theirs.fragmentsLength).toBe(1);
        continue;
      }
      expect(ours.fragmentCount).toBe(theirs.fragmentsLength);
      const frames = ours.fragmentCount * 2 + 5;
      for (let i = 0; i < frames; i++) {
        expect(ours.nextPart().toUpperCase()).toBe(theirs.nextPart().toUpperCase());
      }
    }
  });
});
