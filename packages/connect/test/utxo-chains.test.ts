import { HDKey } from '@scure/bip32';
import { describe, expect, it } from 'vitest';
import {
  btcP2wpkhAddressFromPublicKey,
  nestedSegwitAddressFromPublicKey,
  p2pkhAddressFromPublicKey,
} from '../src/accounts/derive';
import { cborEncode } from '../src/cbor/encode';
import { cbArray, cbBool, cbBytes, cbMap, cbTag, cbUint } from '../src/cbor/model';
import { hexToBytes } from '../src/core/bytes';
import { EraAccounts, Ur } from '../src/index';

/**
 * Litecoin, Dogecoin and Dash: the same base58check/bech32 machinery Bitcoin
 * already uses, under different version bytes. Those bytes come from each
 * coin's `CoinInfo` in the firmware (`BitcoinDispatcher.cpp`) — LTC 48/50,
 * DOGE 30/22, DASH 76/16 — because they are the only thing separating one
 * chain's addresses from another's.
 *
 * The expectations were produced by a standalone stdlib oracle that
 * reproduces the published BIP-44 and BIP-84 Bitcoin vectors for this very
 * seed byte-for-byte (`1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA` and
 * `bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu`), never by this package.
 */
const TEST_SEED = hexToBytes(
  '5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4',
);
const master = HDKey.fromMasterSeed(TEST_SEED);
const keyAt = (path: string) => master.derive(path).publicKey!;

describe('altcoin address encoders', () => {
  it("litecoin native segwit (m/84'/2') is ltc1q…", () => {
    expect(btcP2wpkhAddressFromPublicKey(keyAt("m/84'/2'/0'/0/0"), 'ltc')).toBe(
      'ltc1qjmxnz78nmc8nq77wuxh25n2es7rzm5c2rkk4wh',
    );
  });

  it("litecoin nested segwit (m/49'/2') is M…, not Bitcoin's 3…", () => {
    expect(nestedSegwitAddressFromPublicKey(keyAt("m/49'/2'/0'/0/0"), 50)).toBe(
      'M7wtsL7wSHDBJVMWWhtQfTMSYYkyooAAXM',
    );
  });

  it("litecoin legacy (m/44'/2') is L…", () => {
    expect(p2pkhAddressFromPublicKey(keyAt("m/44'/2'/0'/0/0"), 48)).toBe(
      'LUWPbpM43E2p7ZSh8cyTBEkvpHmr3cB8Ez',
    );
  });

  it('dogecoin is D…', () => {
    expect(p2pkhAddressFromPublicKey(keyAt("m/44'/3'/0'/0/0"), 30)).toBe(
      'DBus3bamQjgJULBJtYXpEzDWQRwF5iwxgC',
    );
  });

  it('dash is X…', () => {
    expect(p2pkhAddressFromPublicKey(keyAt("m/44'/5'/0'/0/0"), 76)).toBe(
      'XoJA8qE3N2Y3jMLEtZ3vcN42qseZ8LvFf5',
    );
  });

  it('the generic encoder still answers Bitcoin under version 0', () => {
    // Proves the machinery under the altcoin constants is the same one the
    // published Bitcoin vectors already pin.
    expect(p2pkhAddressFromPublicKey(keyAt("m/44'/0'/0'/0/0"), 0x00)).toBe(
      '1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA',
    );
  });
});

function levels(list: [number, boolean][]) {
  return cbArray(list.flatMap(([i, h]) => [cbUint(i), cbBool(h)]));
}

function entryAt(path: string, list: [number, boolean][], xfp: number) {
  const node = master.derive(path);
  return cbMap([
    [3, cbBytes(node.publicKey!)],
    [4, cbBytes(node.chainCode!)],
    [
      6,
      cbTag(
        304,
        cbMap([
          [1, levels(list)],
          [2, cbUint(xfp)],
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
        [1, cbUint(master.fingerprint >>> 0)],
        [
          2,
          cbArray([
            entryAt(
              "m/84'/2'/0'",
              [
                [84, true],
                [2, true],
                [0, true],
              ],
              0x11111111,
            ),
            entryAt(
              "m/44'/3'/0'",
              [
                [44, true],
                [3, true],
                [0, true],
              ],
              0x22222222,
            ),
            entryAt(
              "m/44'/5'/0'",
              [
                [44, true],
                [5, true],
                [0, true],
              ],
              0x33333333,
            ),
          ]),
        ],
      ]),
    ),
  ),
);

describe('altcoin account views', () => {
  it('classifies each chain at its own mainnet coin type', () => {
    const byPath = new Map(wallet.keys.map((a) => [a.path, a.chain]));
    expect(byPath.get("m/84'/2'/0'")).toBe('litecoin');
    expect(byPath.get("m/44'/3'/0'")).toBe('dogecoin');
    expect(byPath.get("m/44'/5'/0'")).toBe('dash');
  });

  it('derives receive and change addresses for litecoin', () => {
    const ltc = wallet.litecoin()!;
    expect(ltc.purpose).toBe(84);
    expect(ltc.accountPath).toBe("m/84'/2'/0'");
    expect(ltc.receivePath(0)).toBe("m/84'/2'/0'/0/0");
    expect(ltc.deriveAddress(0)).toBe('ltc1qjmxnz78nmc8nq77wuxh25n2es7rzm5c2rkk4wh');
    expect(ltc.deriveAddress(0, { change: true })).toBe(
      'ltc1qyeljcy9v88jg8sqvnqh0m5q390xruc5r98q9yy',
    );
  });

  it('derives dogecoin and dash', () => {
    expect(wallet.dogecoin()!.deriveAddress(0)).toBe('DBus3bamQjgJULBJtYXpEzDWQRwF5iwxgC');
    expect(wallet.dash()!.deriveAddress(0)).toBe('XoJA8qE3N2Y3jMLEtZ3vcN42qseZ8LvFf5');
  });

  it('answers undefined for a script type the export does not carry', () => {
    expect(wallet.litecoin({ purpose: 44 })).toBeUndefined();
    expect(wallet.litecoin({ purpose: 84 })!.purpose).toBe(84);
  });
});
