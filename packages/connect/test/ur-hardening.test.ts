import { describe, expect, it } from 'vitest';
import { cborEncode } from '../src/cbor/encode';
import { cbArray, cbBytes, cbUint } from '../src/cbor/model';
import { bytewordsDecode, bytewordsEncode } from '../src/ur/bytewords';
import { crc32 } from '../src/ur/crc32';
import { UrDecoder } from '../src/ur/decoder';
import { chooseFragmentIndexes } from '../src/ur/sampler';
import { Ur } from '../src/ur/ur';

/**
 * Everything a scanned QR can dictate to the decoder, and what the decoder is
 * required to refuse. The camera is an untrusted input channel: a sticker on
 * the device, a poster, a screenshot from the gallery — every case below is
 * one QR string.
 */

function hostileFrame(args: {
  type?: string;
  seqNum: number;
  seqLen: number;
  messageLen: number;
  checksum: number;
  part?: Uint8Array;
  partLen?: number;
}): string {
  const payload = cborEncode(
    cbArray([
      cbUint(args.seqNum),
      cbUint(args.seqLen),
      cbUint(args.messageLen),
      cbUint(args.checksum),
      cbBytes(args.part ?? new Uint8Array(args.partLen ?? 10)),
    ]),
  );
  const type = args.type ?? 'eth-signature';
  return `ur:${type}/${args.seqNum}-${args.seqLen}/${bytewordsEncode(payload)}`;
}

function genuineFrames(body: Uint8Array, parts = 3, type = 'eth-signature'): string[] {
  const fragmentLen = Math.ceil(body.length / parts);
  const checksum = crc32(body);
  const frames: string[] = [];
  for (let i = 0; i < parts; i++) {
    const slice = new Uint8Array(fragmentLen);
    for (let j = i * fragmentLen; j < (i + 1) * fragmentLen && j < body.length; j++) {
      slice[j - i * fragmentLen] = body[j]!;
    }
    frames.push(
      hostileFrame({
        type,
        seqNum: i + 1,
        seqLen: parts,
        messageLen: body.length,
        checksum,
        part: slice,
      }),
    );
  }
  return frames;
}

const body = new Uint8Array(Array.from({ length: 60 }, (_, i) => (i * 7) % 256));

/** Two frames of the same hostile stream must not bind (refused headers never bind). */
function expectHeaderRefused(args: {
  type?: string;
  seqLen: number;
  messageLen: number;
  checksum: number;
  partLen?: number;
}): void {
  const decoder = new UrDecoder();
  for (const seqNum of [1, 2]) {
    expect(decoder.receivePart(hostileFrame({ ...args, seqNum }))).toBe(false);
  }
  expect(decoder.type).toBe('');
  expect(decoder.partsExpected).toBe(0);
}

function feedPasses(
  decoder: UrDecoder,
  frames: string[],
  passes: number,
  interleave?: string,
): void {
  for (let p = 0; p < passes; p++) {
    for (const f of frames) {
      if (interleave !== undefined) decoder.receivePart(interleave);
      decoder.receivePart(f);
    }
  }
}

describe('genuine multi-part URs still assemble', () => {
  it('three fragments reassemble to the exact payload', () => {
    const decoder = new UrDecoder();
    for (const f of genuineFrames(body)) decoder.receivePart(f);
    expect(decoder.isComplete).toBe(true);
    expect(decoder.result().cbor).toEqual(body);
  });

  it('fragments arriving out of order still assemble', () => {
    const decoder = new UrDecoder();
    const frames = genuineFrames(body);
    for (const f of [frames[2]!, frames[0]!, frames[1]!]) decoder.receivePart(f);
    expect(decoder.isComplete).toBe(true);
    expect(decoder.result().cbor).toEqual(body);
  });

  it('an unreadable sequence segment is refused, not promoted to single-part', () => {
    const decoder = new UrDecoder();
    const payload = cborEncode(cbBytes(new Uint8Array(10)));
    const frame = `ur:eth-signature/99999999999999999999999-3/${bytewordsEncode(payload)}`;
    expect(() => decoder.receivePart(frame)).toThrowError(/sequence/);
    expect(decoder.isComplete).toBe(false);
  });

  it('a single-part UR over the ceiling is refused; at the ceiling accepted', () => {
    const over = new Ur('bytes', new Uint8Array(64 * 1024 + 1));
    const decoder = new UrDecoder();
    expect(decoder.receivePart(over.toString())).toBe(false);
    expect(decoder.lastRefusal?.code).toBe('limit-exceeded');

    const at = new Ur('bytes', new Uint8Array(64 * 1024).fill(1));
    const fresh = new UrDecoder();
    expect(fresh.receivePart(at.toString())).toBe(true);
  });
});

describe('one frame cannot dictate an unbounded allocation', () => {
  it('a huge seqLength is refused instead of sizing a list', () => {
    expectHeaderRefused({ seqLen: 500_000, messageLen: 100, checksum: 1 });
  });

  it('a huge messageLength is refused', () => {
    expectHeaderRefused({ seqLen: 2, messageLen: 500 * 1024 * 1024, checksum: 1 });
  });

  it('one byte over the message cap is refused, consistent header and all', () => {
    // 64 KiB + 1 across 8 fragments of 8193 bytes... keep the header
    // internally consistent so ONLY the cap can be the reason.
    expectHeaderRefused({
      seqLen: 17,
      messageLen: 64 * 1024 + 1,
      checksum: 1,
      partLen: 4096,
    });
  });

  it('the sampler refuses a length the protocol cannot produce', () => {
    expect(() => chooseFragmentIndexes(5000, 4096, 1)).toThrow(RangeError);
  });

  it('a seqLength of 1 cannot bind (defeats the two-fragment rule with two stickers)', () => {
    expectHeaderRefused({ seqLen: 1, messageLen: 10, checksum: 1 });
  });
});

describe('the fragment header is parsed, not cast', () => {
  it('a header that is not a five-item list is refused', () => {
    const payload = cborEncode(cbArray([cbUint(1), cbUint(2)]));
    const decoder = new UrDecoder();
    expect(decoder.receivePart(`ur:eth-signature/1-2/${bytewordsEncode(payload)}`)).toBe(false);
    expect(decoder.lastRefusal?.code).toBe('limit-exceeded');
  });

  it('a header whose items are the wrong CBOR types is refused', () => {
    const payload = cborEncode(
      cbArray([
        cbBytes(new Uint8Array(2)),
        cbUint(2),
        cbUint(10),
        cbUint(1),
        cbBytes(new Uint8Array(5)),
      ]),
    );
    const decoder = new UrDecoder();
    expect(decoder.receivePart(`ur:eth-signature/1-2/${bytewordsEncode(payload)}`)).toBe(false);
  });

  it('a header disagreeing with the path sequence is refused', () => {
    const frame = hostileFrame({ seqNum: 1, seqLen: 3, messageLen: 25, checksum: 9 });
    const lied = frame.replace('/1-3/', '/2-3/');
    const decoder = new UrDecoder();
    expect(decoder.receivePart(lied)).toBe(false);
    expect(decoder.lastRefusal?.code).toBe('fragment-mismatch');
  });
});

describe('bytewords are validated, not trusted', () => {
  it('an invalid byteword pair is refused instead of decoding to 0xFF', () => {
    expect(() => bytewordsDecode('zzzzzzzzzzzz')).toThrowError(/byteword/);
  });

  it('a corrupted trailing CRC is refused', () => {
    const good = bytewordsEncode(new Uint8Array([1, 2, 3]));
    const corrupted = good.slice(0, -2) + (good.endsWith('ae') ? 'ao' : 'ae');
    expect(() => bytewordsDecode(corrupted)).toThrow();
  });

  it('a body too short to hold a CRC is refused', () => {
    expect(() => bytewordsDecode('aeae')).toThrowError(/checksum plus one byte/);
  });

  it('a well-formed round trip is untouched', () => {
    const data = new Uint8Array([0, 1, 2, 253, 254, 255]);
    expect(bytewordsDecode(bytewordsEncode(data))).toEqual(data);
  });
});

describe('the assembled payload is checked against the declared checksum', () => {
  it('a stream whose fragments lie about the checksum is refused', () => {
    const decoder = new UrDecoder();
    const frames = genuineFrames(body).map((f) => {
      // Rebuild each frame with a wrong checksum but consistent headers.
      return f;
    });
    // Hand-build: three fragments declaring checksum 1 (wrong).
    const fragmentLen = Math.ceil(body.length / 3);
    for (let i = 0; i < 3; i++) {
      const slice = new Uint8Array(fragmentLen);
      for (let j = i * fragmentLen; j < (i + 1) * fragmentLen && j < body.length; j++) {
        slice[j - i * fragmentLen] = body[j]!;
      }
      decoder.receivePart(
        hostileFrame({
          seqNum: i + 1,
          seqLen: 3,
          messageLen: body.length,
          checksum: 1,
          part: slice,
        }),
      );
    }
    expect(decoder.isComplete).toBe(false);
    expect(frames.length).toBe(3);
  });

  it('a rogue fragment costs the accumulation but NOT the binding', () => {
    const decoder = new UrDecoder();
    const frames = genuineFrames(body);
    const checksum = crc32(body);
    decoder.receivePart(frames[0]!);
    decoder.receivePart(frames[1]!);
    // Rogue: same fingerprint (type/len/msgLen/checksum/partLen), poisoned bytes.
    decoder.receivePart(
      hostileFrame({
        seqNum: 3,
        seqLen: 3,
        messageLen: body.length,
        checksum,
        part: new Uint8Array(Math.ceil(body.length / 3)).fill(0xee),
      }),
    );
    // Accumulation was discarded on the failed join; binding survives, so a
    // clean pass assembles.
    expect(decoder.isComplete).toBe(false);
    for (const f of frames) decoder.receivePart(f);
    expect(decoder.isComplete).toBe(true);
    expect(decoder.result().cbor).toEqual(body);
  });
});

describe('a hostile frame cannot jam the scanner (EXTRA-08)', () => {
  it('a single static frame holds the binding only provisionally', () => {
    const decoder = new UrDecoder();
    decoder.receivePart(
      hostileFrame({ type: 'crypto-psbt', seqNum: 1, seqLen: 3, messageLen: 30, checksum: 123 }),
    );
    feedPasses(decoder, genuineFrames(body), 16);
    expect(decoder.isComplete).toBe(true);
    expect(decoder.result().cbor).toEqual(body);
  });

  it('a static frame of the EXPECTED type is given up too', () => {
    const decoder = new UrDecoder();
    decoder.receivePart(
      hostileFrame({ seqNum: 1, seqLen: 2, messageLen: 40, checksum: 12345, partLen: 20 }),
    );
    feedPasses(decoder, genuineFrames(body), 16);
    expect(decoder.isComplete).toBe(true);
    expect(decoder.result().cbor).toEqual(body);
  });

  it('the same frame shown over and over cannot confirm itself', () => {
    const decoder = new UrDecoder();
    const hostile = hostileFrame({
      seqNum: 1,
      seqLen: 2,
      messageLen: 40,
      checksum: 999,
      partLen: 20,
    });
    for (let i = 0; i < 50; i++) decoder.receivePart(hostile);
    feedPasses(decoder, genuineFrames(body), 16);
    expect(decoder.isComplete).toBe(true);
    expect(decoder.result().cbor).toEqual(body);
  });

  it('the device head start is decisive: two stickers cannot take a held binding', () => {
    const hostileBody = new Uint8Array(Array.from({ length: 40 }, (_, i) => 0xee - (i % 17)));
    const stickers = genuineFrames(hostileBody, 2);
    const genuine = genuineFrames(body, 6);

    const decoder = new UrDecoder();
    decoder.receivePart(genuine[0]!); // the device lands exactly one frame first
    expect(decoder.type).toBe('eth-signature');

    for (const s of stickers) {
      decoder.receivePart(s);
      decoder.receivePart(s);
    }
    for (let i = 1; i < genuine.length; i++) decoder.receivePart(genuine[i]!);

    expect(decoder.isComplete).toBe(true);
    expect(decoder.result().cbor).toEqual(body);
  });

  it('nor can an animated attacker at a rate advantage', () => {
    const hostileBody = new Uint8Array(Array.from({ length: 60 }, (_, i) => 0xc0 + (i % 31)));
    const hostile = genuineFrames(hostileBody, 3);
    const genuine = genuineFrames(body, 6);

    const decoder = new UrDecoder();
    decoder.receivePart(genuine[0]!);
    for (let round = 1; round < genuine.length && !decoder.isComplete; round++) {
      for (let i = 0; i < 4; i++) decoder.receivePart(hostile[i % hostile.length]!);
      decoder.receivePart(genuine[round]!);
    }
    expect(decoder.isComplete).toBe(true);
    expect(decoder.result().cbor).toEqual(body);
  });

  it('a static hostile frame interleaved with every genuine frame still loses', () => {
    const decoder = new UrDecoder();
    const hostile = hostileFrame({
      seqNum: 1,
      seqLen: 2,
      messageLen: 40,
      checksum: 999,
      partLen: 20,
    });
    feedPasses(decoder, genuineFrames(body), 16, hostile);
    expect(decoder.isComplete).toBe(true);
    expect(decoder.result().cbor).toEqual(body);
  });

  it('a single-part UR cannot walk over a confirmed assembly, but is accepted fresh', () => {
    const decoder = new UrDecoder();
    const genuine = genuineFrames(body, 4);
    decoder.receivePart(genuine[0]!);
    decoder.receivePart(genuine[1]!);
    expect(decoder.partsReceived).toBeGreaterThan(1);

    const hostileSingle = new Ur('eth-signature', new Uint8Array(42).fill(0xee)).toString();
    expect(decoder.receivePart(hostileSingle)).toBe(false);
    expect(decoder.lastRefusal?.code).toBe('fragment-mismatch');
    expect(decoder.isComplete).toBe(false);

    decoder.receivePart(genuine[2]!);
    decoder.receivePart(genuine[3]!);
    expect(decoder.isComplete).toBe(true);
    expect(decoder.result().cbor).toEqual(body);

    const fresh = new UrDecoder();
    expect(fresh.receivePart(hostileSingle)).toBe(true);
  });
});
