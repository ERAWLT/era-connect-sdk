import { describe, expect, it } from 'vitest';
import { cborEncode } from '../src/cbor/encode';
import { cbArray, cbBool, cbBytes, cbMap, cbTag, cbUint } from '../src/cbor/model';
import { EraAccounts, Ur } from '../src/index';

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
    [6, cbTag(304, cbMap([[1, levels(list)], [2, cbUint(0x11111111)]]))],
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
            solEntry([[44, true], [501, true]], 0x01),
            solEntry([[44, true], [501, true], [0, true]], 0x02),
            solEntry([[44, true], [501, true], [0, true], [0, true]], 0x03),
            solEntry([[44, true], [501, true], [1, true]], 0x04),
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
