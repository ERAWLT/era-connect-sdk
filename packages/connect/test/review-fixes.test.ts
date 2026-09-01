import { HDKey } from '@scure/bip32';
import { describe, expect, it } from 'vitest';
import { cborDecode } from '../src/cbor/decode';
import { cborEncode } from '../src/cbor/encode';
import {
  asArray,
  asMap,
  cbArray,
  cbBool,
  cbBytes,
  cbMap,
  cbTag,
  cbUint,
  mapGet,
} from '../src/cbor/model';
import { concatBytes, hexToBytes, utf8Decode } from '../src/core/bytes';
import { EraAccounts, EraConnect, EraSdkError, Ur } from '../src/index';
import { gunzipCapped, gzipCompress } from '../src/tron-proto/gzip';

/** Regression tests for the pre-release adversarial review findings. */

const era = new EraConnect({ origin: 'Review' });

describe('qr-hardware-call encodes and round-trips (review: depth cap)', () => {
  it('builds, decodes and carries the requested schemas', () => {
    const call = era.generateKeyDerivationCall({
      schemas: [{ path: "m/44'/60'/0'" }, { path: "m/44'/501'/3'", curve: 'ed25519' }],
    });
    expect(call.ur.type).toBe('qr-hardware-call');
    expect(call.replyTypes).toContain('crypto-multi-accounts');

    const root = asMap(cborDecode(call.ur.cbor))!;
    expect(mapGet(root, 1)).toEqual(cbUint(0)); // type: KeyDerivation
    const params = mapGet(root, 2)!;
    expect(params.kind === 'tag' && params.tag).toBe(1301);
    const schemas = asArray(mapGet(asMap(params)!, 1))!;
    expect(schemas.length).toBe(2);
    const second = asMap(schemas[1])!;
    expect(mapGet(second, 2)).toEqual(cbUint(1)); // ed25519

    // The animated form works too (single frame for a small call).
    expect(call.toAnimated().nextFrame().startsWith('UR:QR-HARDWARE-CALL/')).toBe(true);
  });
});

describe('gzip trailer CRC (review: parity with the reference decoder)', () => {
  const payload = new Uint8Array(Array.from({ length: 300 }, (_, i) => i % 251));

  it('a flipped CRC byte is refused', () => {
    const blob = gzipCompress(payload);
    blob[blob.length - 8] = blob[blob.length - 8]! ^ 0xff;
    expect(() => gunzipCapped(blob, 64 * 1024)).toThrowError(/CRC/);
  });

  it('a concatenated multi-member stream is refused', () => {
    const a = gzipCompress(new Uint8Array(100).fill(1));
    const b = gzipCompress(new Uint8Array(112).fill(2));
    const joined = concatBytes(a, b);
    // Patch the final ISIZE to the combined length so only the CRC can refuse.
    const total = 212;
    joined[joined.length - 4] = total & 0xff;
    joined[joined.length - 3] = 0;
    joined[joined.length - 2] = 0;
    joined[joined.length - 1] = 0;
    expect(() => gunzipCapped(joined, 64 * 1024)).toThrow();
  });

  it('honest payloads still round-trip', () => {
    expect(gunzipCapped(gzipCompress(payload), 64 * 1024)).toEqual(payload);
  });
});

describe('strict UTF-8 (review: overlong/surrogate smuggling)', () => {
  it('rejects overlong encodings', () => {
    expect(() => utf8Decode(new Uint8Array([0xc0, 0x80]))).toThrowError(/overlong/);
  });
  it('rejects encoded surrogates', () => {
    expect(() => utf8Decode(new Uint8Array([0xed, 0xa0, 0x80]))).toThrowError(/surrogate/);
  });
  it('rejects code points past U+10FFFF', () => {
    expect(() => utf8Decode(new Uint8Array([0xf5, 0x80, 0x80, 0x80]))).toThrow();
  });
  it('accepts real multi-byte text', () => {
    const bytes = new Uint8Array([0xe2, 0x82, 0xac, 0xf0, 0x9f, 0x94, 0x91]); // € 🔑
    expect(utf8Decode(bytes)).toBe('€🔑');
  });
});

// --- wallet exports with imperfect entries + BTC purposes ------------------

const TEST_SEED = hexToBytes(
  '5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4',
);

function comps(levels: [number, boolean][]) {
  const items = [];
  for (const [i, h] of levels) items.push(cbUint(i), cbBool(h));
  return cbArray(items);
}

function entryOf(levels: [number, boolean][], xfp: number, node?: HDKey) {
  const inner: [number, ReturnType<typeof cbUint>][] = [
    [
      6,
      cbTag(
        304,
        cbMap([
          [1, comps(levels)],
          [2, cbUint(xfp)],
        ]),
      ),
    ],
  ];
  if (node) {
    inner.unshift([3, cbBytes(node.publicKey!)], [4, cbBytes(node.chainCode!)]);
    inner.push([8, cbUint(node.parentFingerprint >>> 0)]);
  }
  return cbMap(inner);
}

describe('wallet exports (review: keyless entries, BTC purposes)', () => {
  const master = HDKey.fromMasterSeed(TEST_SEED);
  const wallet = EraAccounts.fromUr(
    new Ur(
      'crypto-multi-accounts',
      cborEncode(
        cbMap([
          [1, cbUint(master.fingerprint >>> 0)],
          [
            2,
            cbArray([
              entryOf(
                [
                  [44, true],
                  [60, true],
                  [0, true],
                ],
                0x11111111,
              ), // NO public key
              entryOf(
                [
                  [84, true],
                  [0, true],
                  [0, true],
                ],
                0x22222222,
                master.derive("m/84'/0'/0'"),
              ),
              entryOf(
                [
                  [44, true],
                  [0, true],
                  [0, true],
                ],
                0x33333333,
                master.derive("m/44'/0'/0'"),
              ),
              entryOf(
                [
                  [49, true],
                  [0, true],
                  [0, true],
                ],
                0x44444444,
                master.derive("m/49'/0'/0'"),
              ),
            ]),
          ],
        ]),
      ),
    ),
  );

  it('an entry without a public key still resolves its xfp (reference parity)', () => {
    expect(wallet.xfpFor("m/44'/60'/0'")).toBe('11111111');
    expect(wallet.evm()?.xfp).toBe('11111111');
    expect(() => wallet.evm()!.deriveAddress(0)).toThrowError(EraSdkError);
  });

  it('derives the canonical BIP-44 legacy address (message-signing kind)', () => {
    const legacy = wallet.btc({ purpose: 44 })!;
    expect(legacy.deriveAddress(0)).toBe('1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA');
    expect(legacy.receivePath(0)).toBe("m/44'/0'/0'/0/0");
  });

  it('derives the canonical BIP-49 nested segwit address', () => {
    const nested = wallet.btc({ purpose: 49 })!;
    expect(nested.deriveAddress(0)).toBe('37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf');
  });

  it('zpub stays a BIP-84 concept', () => {
    expect(() => wallet.btc({ purpose: 44 })!.zpub()).toThrowError(/BIP-84/);
    expect(wallet.btc()!.zpub().startsWith('zpub')).toBe(true);
  });
});

describe('attacker-sized UR types are truncated in errors (review)', () => {
  it('parseAccounts truncates the reported type', () => {
    const longType = `a${'b'.repeat(500)}`;
    try {
      era.parseAccounts(new Ur(longType, cborEncode(cbMap([[1, cbUint(1)]]))));
      expect.unreachable();
    } catch (e) {
      const err = e as EraSdkError;
      expect(err.code).toBe('wrong-ur-type');
      expect(err.message.length).toBeLessThan(200);
    }
  });
});

describe('gzip reserved FLG bits (cross-SDK contract)', () => {
  it('refuses a stream with any reserved header flag bit set', async () => {
    const { gzipCompress, gunzipCapped } = await import('../src/tron-proto/gzip');
    const good = gzipCompress(new Uint8Array(64).fill(7));
    expect(gunzipCapped(good, 1024)).toHaveLength(64);
    for (const bit of [0x20, 0x40, 0x80]) {
      const bad = Uint8Array.from(good);
      bad[3]! |= bit;
      expect(() => gunzipCapped(bad, 1024)).toThrow(/reserved header flag bits/);
    }
  });
});
