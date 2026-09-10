import { describe, expect, it } from 'vitest';
import { cborDecode } from '../src/cbor/decode';
import { cborEncode } from '../src/cbor/encode';
import {
  cbArray,
  cbBool,
  cbBytes,
  cbMap,
  cbTag,
  cbUint,
  mapGet,
  stripTags,
} from '../src/cbor/model';
import { EraSdkError } from '../src/core/errors';
import { EraAccounts, EraConnect, Ur } from '../src/index';
import { parsePathComponents } from '../src/registry/keypath';

/**
 * The device ships all three Solana derivations, and the firmware tells them
 * apart by PATH DEPTH alone — all three carry the same `Derivation::Solana`.
 * Read `index` without `scheme` and three different accounts all claim to be
 * number 0.
 */
function levels(list: [number, boolean][]) {
  return cbArray(list.flatMap(([i, h]) => [cbUint(i), cbBool(h)]));
}

function solEntry(list: [number, boolean][], keyByte: number) {
  return cbMap([
    [3, cbBytes(new Uint8Array(32).fill(keyByte))],
    [
      6,
      cbTag(
        304,
        cbMap([
          [1, levels(list)],
          [2, cbUint(0x11111111)],
        ]),
      ),
    ],
  ]);
}

const wallet = EraAccounts.fromUr(
  new Ur(
    'crypto-multi-accounts',
    cborEncode(
      cbMap([
        [1, cbUint(0x12345678)],
        [
          2,
          cbArray([
            solEntry(
              [
                [44, true],
                [501, true],
              ],
              0x01,
            ),
            solEntry(
              [
                [44, true],
                [501, true],
                [0, true],
              ],
              0x02,
            ),
            solEntry(
              [
                [44, true],
                [501, true],
                [0, true],
                [0, true],
              ],
              0x03,
            ),
            solEntry(
              [
                [44, true],
                [501, true],
                [1, true],
              ],
              0x04,
            ),
          ]),
        ],
      ]),
    ),
  ),
);

describe('Solana derivation schemes', () => {
  it('three entries claim index 0 — the scheme is what separates them', () => {
    const zero = wallet.solana().filter((v) => v.index === 0);
    expect(zero).toHaveLength(3);
    expect(zero.map((v) => v.scheme)).toEqual(['single', 'account', 'sub-account']);
    expect(new Set(zero.map((v) => v.address)).size).toBe(3);
  });

  it('reads the scheme off the path depth', () => {
    const byPath = new Map(wallet.solana().map((v) => [v.path, v.scheme]));
    expect(byPath.get("m/44'/501'")).toBe('single');
    expect(byPath.get("m/44'/501'/0'")).toBe('account');
    expect(byPath.get("m/44'/501'/0'/0'")).toBe('sub-account');
    expect(byPath.get("m/44'/501'/1'")).toBe('account');
  });

  it('filters to one scheme, which is what a wallet actually wants', () => {
    const accounts = wallet.solana({ scheme: 'account' });
    expect(accounts.map((v) => v.path)).toEqual(["m/44'/501'/0'", "m/44'/501'/1'"]);
    expect(accounts.map((v) => v.index)).toEqual([0, 1]);
    expect(wallet.solana({ scheme: 'single' })).toHaveLength(1);
    expect(wallet.solana({ scheme: 'sub-account' })).toHaveLength(1);
  });

  it('an unfiltered list is still every key the export shipped', () => {
    expect(wallet.solana()).toHaveLength(4);
  });
});

describe('a sign request carries the scheme it was built for', () => {
  // The device signs at the FULL path the request names, so the depth IS the
  // key selector. This guard used to demand exactly three levels, which made
  // the address the device's own Receive screen shows by default — the
  // 2-level `m/44'/501'` — unsignable through the SDK.
  const era = new EraConnect({ origin: 'Test Wallet' });
  const pubkey = new Uint8Array(32).fill(0x09);
  const requestId = new Uint8Array(16).fill(0x01);
  const signData = new Uint8Array(48).fill(0x02);

  function urFor(path: string) {
    return era.solana.generateSignRequest({
      requestId,
      signData,
      path,
      xfp: '33333333',
      publicKey: pubkey,
    }).ur;
  }

  /** `crypto-keypath` (tag 304) key 1, back out of the flat pair array. */
  function levelsOf(path: string) {
    const keypath = stripTags(mapGet(cborDecode(urFor(path).cbor), 3)!);
    return parsePathComponents(mapGet(keypath, 1))!.map((l) => [l.index, l.hardened] as const);
  }

  it("the single-account path m/44'/501' encodes two hardened levels", () => {
    expect(levelsOf("m/44'/501'")).toEqual([
      [44, true],
      [501, true],
    ]);
  });

  it("the account path m/44'/501'/idx' still encodes three", () => {
    expect(levelsOf("m/44'/501'/3'")).toEqual([
      [44, true],
      [501, true],
      [3, true],
    ]);
  });

  it("the sub-account path m/44'/501'/idx'/0' encodes four", () => {
    expect(levelsOf("m/44'/501'/3'/0'")).toEqual([
      [44, true],
      [501, true],
      [3, true],
      [0, true],
    ]);
  });

  it('a depth outside 2..4 is refused', () => {
    for (const path of ["m/44'", "m/44'/501'/0'/0'/0'"]) {
      expect(() => urFor(path)).toThrow(EraSdkError);
    }
  });

  it('an unhardened level is refused at every depth', () => {
    for (const path of ['m/44/501', "m/44'/501'/0", "m/44'/501'/0'/0"]) {
      expect(() => urFor(path)).toThrow(EraSdkError);
    }
  });

  it('the coin type is deliberately not policed', () => {
    // The guard never checked it. Tightening that here would refuse paths that
    // sign on the device today, in a release that only claims to ACCEPT more.
    expect(() => urFor("m/44'/784'/0'")).not.toThrow();
  });
});
