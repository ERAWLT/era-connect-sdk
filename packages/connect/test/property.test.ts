import { encode as cbor2Encode, Tag } from 'cbor2';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { cborDecode } from '../src/cbor/decode';
import { cborEncode } from '../src/cbor/encode';
import type { CborValue } from '../src/cbor/model';
import { cbArray, cbBool, cbBytes, cbMap, cbTag, cbText, cbUint } from '../src/cbor/model';
import { bytesToHex } from '../src/core/bytes';
import { UrScanner } from '../src/scan/ur-scanner';
import { gunzipCapped, gzipCompress } from '../src/tron-proto/gzip';
import { decodeSignResultProto, splitSignedTronTx } from '../src/tron-proto/messages';
import { readFields } from '../src/tron-proto/wire';
import { UrDecoder } from '../src/ur/decoder';
import { UrFountainEncoder } from '../src/ur/encoder';
import { headerIsConsistent, UrLimits } from '../src/ur/limits';
import { Ur } from '../src/ur/ur';

// CI default; the nightly fuzz job scales this up via FC_NUM_RUNS.
const BASE_RUNS = Number(process.env.FC_NUM_RUNS) || 200;
const RUNS = { numRuns: BASE_RUNS };
const MANY_RUNS = { numRuns: Math.max(BASE_RUNS * 10, 2000) };

describe('fountain code properties', () => {
  it('assembles from any sufficient subset: drop, duplicate, reorder', () => {
    fc.assert(
      fc.property(
        fc.uint8Array({ minLength: 1, maxLength: 3000 }),
        fc.integer({ min: 10, max: 200 }),
        fc.integer({ min: 0, max: 2 ** 31 - 1 }),
        (payload, fragLen, shuffleSeed) => {
          const encoder = new UrFountainEncoder(new Ur('bytes', payload), fragLen, 10);
          const frames: string[] = [];
          const budget = encoder.fragmentCount * 3 + 3;
          for (let i = 0; i < budget; i++) frames.push(encoder.nextPart());

          // Deterministic shuffle + duplicate every third frame.
          let s = shuffleSeed >>> 0 || 1;
          const rnd = () => {
            s ^= s << 13;
            s ^= s >>> 17;
            s ^= s << 5;
            return (s >>> 0) / 2 ** 32;
          };
          const fed = [...frames, ...frames.filter((_, i) => i % 3 === 0)];
          fed.sort(() => rnd() - 0.5);

          const decoder = new UrDecoder();
          let complete = false;
          for (const frame of fed) complete = decoder.receivePart(frame) || complete;
          return complete && bytesToHex(decoder.result().cbor) === bytesToHex(payload);
        },
      ),
      RUNS,
    );
  });

  it('no accepted header can allocate past the caps', () => {
    fc.assert(
      fc.property(
        fc.record({
          seqNum: fc.integer({ min: -10, max: 2 ** 31 }),
          seqLength: fc.integer({ min: -10, max: 2 ** 31 }),
          messageLength: fc.integer({ min: -10, max: 2 ** 31 }),
          checksum: fc.integer({ min: -10, max: 2 ** 31 }),
          fragmentLength: fc.integer({ min: -10, max: 2 ** 31 }),
        }),
        (header) => {
          if (!headerIsConsistent(header)) return true;
          return (
            header.messageLength <= UrLimits.maxMessageBytes &&
            header.seqLength <= UrLimits.maxFragmentCount &&
            header.fragmentLength <= UrLimits.maxFragmentBytes &&
            header.messageLength <= header.seqLength * header.fragmentLength &&
            header.messageLength > (header.seqLength - 1) * header.fragmentLength
          );
        },
      ),
      MANY_RUNS,
    );
  });
});

describe('the scanner never throws on arbitrary frames', () => {
  it('arbitrary strings produce results, not exceptions', () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 300 }), (text) => {
        const scanner = new UrScanner({ expectedTypes: ['eth-signature'] });
        const result = scanner.receivePart(text);
        return ['progress', 'duplicate', 'rejected', 'complete'].includes(result.kind);
      }),
      MANY_RUNS,
    );
  });

  it('arbitrary bytes dressed as bytewords produce results, not exceptions', () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 1, maxLength: 200 }), (bytes) => {
        const letters = Array.from(bytes, (b) => 'abcdefghijklmnopqrstuvwxyz'[b % 26]).join('');
        const scanner = new UrScanner();
        const result = scanner.receivePart(`ur:bytes/${letters}`);
        return ['progress', 'duplicate', 'rejected', 'complete'].includes(result.kind);
      }),
      MANY_RUNS,
    );
  });
});

// --- CBOR differential vs cbor2 -------------------------------------------

const cborValueArb: fc.Arbitrary<CborValue> = fc.letrec<{ value: CborValue }>((tie) => ({
  value: fc.oneof(
    { maxDepth: 4, withCrossShrink: true },
    fc.bigInt({ min: 0n, max: (1n << 64n) - 1n }).map(cbUint),
    fc.uint8Array({ maxLength: 40 }).map(cbBytes),
    fc.string({ maxLength: 20, unit: 'grapheme-ascii' }).map(cbText),
    fc.boolean().map(cbBool),
    fc.array(tie('value'), { maxLength: 4 }).map((items) => cbArray(items as CborValue[])),
    fc
      .array(fc.tuple(fc.integer({ min: 0, max: 100 }), tie('value')), { maxLength: 4 })
      .map((entries) => {
        const seen = new Set<number>();
        const unique = (entries as [number, CborValue][]).filter(([k]) => {
          if (seen.has(k)) return false;
          seen.add(k);
          return true;
        });
        return cbMap(unique);
      }),
    fc
      // Protocol tags only: semantic tags (0/1 datetime, 2/3 bignum) are
      // TRANSFORMED by general-purpose codecs, which is exactly why the
      // protocol never uses them.
      .tuple(fc.constantFrom(37, 304, 305, 310, 1103, 1301, 1302), tie('value'))
      .map(([tag, value]) => cbTag(tag, value as CborValue)),
  ),
})).value;

function toJsShape(value: CborValue): unknown {
  switch (value.kind) {
    case 'uint':
      return value.value;
    case 'nint':
      return -1n - value.value;
    case 'bytes':
      return value.value;
    case 'text':
      return value.value;
    case 'bool':
      return value.value;
    case 'null':
      return null;
    case 'array':
      return value.items.map(toJsShape);
    case 'map': {
      const map = new Map<unknown, unknown>();
      for (const [k, v] of value.entries) map.set(toJsShape(k), toJsShape(v));
      return map;
    }
    case 'tag':
      return new Tag(value.tag, toJsShape(value.value));
  }
}

describe('CBOR differential vs cbor2', () => {
  it('our encoder emits the same bytes as cbor2 for the same value tree', () => {
    fc.assert(
      fc.property(cborValueArb, (value) => {
        const ours = cborEncode(value);
        const theirs = new Uint8Array(
          cbor2Encode(toJsShape(value), { collapseBigInts: true, largeNegativeAsBigInt: false }),
        );
        return bytesToHex(ours) === bytesToHex(theirs);
      }),
      RUNS,
    );
  });

  it('our decoder round-trips what our encoder emits', () => {
    fc.assert(
      fc.property(cborValueArb, (value) => {
        const bytes = cborEncode(value);
        return bytesToHex(cborEncode(cborDecode(bytes))) === bytesToHex(bytes);
      }),
      RUNS,
    );
  });

  it('hostile CBOR is a typed error, never a crash', () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 1, maxLength: 100 }), (bytes) => {
        let decoded: CborValue | null = null;
        try {
          decoded = cborDecode(bytes);
        } catch (e) {
          return (e as { code?: string }).code === 'malformed-cbor';
        }
        // Whatever we accept re-encodes canonically (definite, minimal
        // width), and canonicalization is idempotent: decode∘encode is a
        // fixed point. (The decoder tolerates non-minimal length heads, as
        // the reference implementation does — a stricter refusal could turn
        // away a genuine reply.)
        const canonical = cborEncode(decoded);
        return bytesToHex(cborEncode(cborDecode(canonical))) === bytesToHex(canonical);
      }),
      MANY_RUNS,
    );
  });
});

describe('protobuf and gzip hardening', () => {
  it('arbitrary bytes into the field reader: typed error or fields, bounded', () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 300 }), (bytes) => {
        try {
          readFields(bytes);
        } catch (e) {
          return (e as { code?: string }).code === 'protobuf-error';
        }
        return true;
      }),
      MANY_RUNS,
    );
  });

  it('arbitrary bytes into the result decoder and tx splitter never crash untyped', () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 200 }), (bytes) => {
        for (const fn of [
          () => decodeSignResultProto(bytes),
          () => splitSignedTronTx(bytesToHex(bytes)),
        ]) {
          try {
            fn();
          } catch (e) {
            if (!(e as { code?: string }).code) return false;
          }
        }
        return true;
      }),
      MANY_RUNS,
    );
  });

  it('a 100 MB zero bomb is refused cheaply; honest payloads round-trip', () => {
    const bomb = gzipCompress(new Uint8Array(100 * 1024 * 1024));
    expect(bomb.length).toBeLessThan(200 * 1024);
    const start = performance.now();
    expect(() => gunzipCapped(bomb, 64 * 1024)).toThrowError(/ceiling/);
    expect(performance.now() - start).toBeLessThan(200);

    const honest = new Uint8Array(Array.from({ length: 5000 }, (_, i) => i % 251));
    expect(gunzipCapped(gzipCompress(honest), 64 * 1024)).toEqual(honest);
  });

  it('a truncated gzip stream is refused via the ISIZE check', () => {
    const honest = gzipCompress(new Uint8Array(2000).fill(7));
    const truncated = honest.slice(0, honest.length - 30);
    // Keep a plausible trailer so only the truncation check can catch it.
    const patched = new Uint8Array([...truncated, ...honest.slice(honest.length - 8)]);
    expect(() => gunzipCapped(patched, 64 * 1024)).toThrow();
  });
});
