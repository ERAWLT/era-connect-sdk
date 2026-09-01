import { HDKey } from '@scure/bip32';
import { describe, expect, it } from 'vitest';
import { cborEncode } from '../src/cbor/encode';
import type { CborValue } from '../src/cbor/model';
import { cbArray, cbBool, cbBytes, cbMap, cbTag, cbText, cbUint } from '../src/cbor/model';
import { hexToBytes } from '../src/core/bytes';
import { EraAccounts, EraSdkError, Ur } from '../src/index';

/**
 * Address derivation against PUBLIC standard vectors: the BIP-84 test seed
 * (the well-known test mnemonic). If any remembered constant here were wrong,
 * the two independent halves (seed-side derivation vs published addresses)
 * could not agree.
 */
const TEST_SEED = hexToBytes(
  '5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4',
);

function pathComponents(levels: [number, boolean][]): CborValue {
  const items: CborValue[] = [];
  for (const [index, hardened] of levels) items.push(cbUint(index), cbBool(hardened));
  return cbArray(items);
}

function accountEntry(
  node: HDKey,
  levels: [number, boolean][],
  extras: [number, CborValue][] = [],
): CborValue {
  return cbMap([
    [3, cbBytes(node.publicKey!)],
    [4, cbBytes(node.chainCode!)],
    [
      6,
      cbTag(
        304,
        cbMap([
          [1, pathComponents(levels)],
          [2, cbUint(0x12345678)],
        ]),
      ),
    ],
    [8, cbUint(node.parentFingerprint >>> 0)],
    ...extras,
  ]);
}

function buildWallet(): EraAccounts {
  const master = HDKey.fromMasterSeed(TEST_SEED);
  const evm = master.derive("m/44'/60'/0'");
  const btc = master.derive("m/84'/0'/0'");
  const tron = master.derive("m/44'/195'/0'");
  const walletCbor = cborEncode(
    cbMap([
      [1, cbUint(master.fingerprint >>> 0)],
      [
        2,
        cbArray([
          accountEntry(
            evm,
            [
              [44, true],
              [60, true],
              [0, true],
            ],
            [[9, cbText('Account 1')]],
          ),
          accountEntry(btc, [
            [84, true],
            [0, true],
            [0, true],
          ]),
          accountEntry(tron, [
            [44, true],
            [195, true],
            [0, true],
          ]),
        ]),
      ],
      [3, cbText('ERA Wallet')],
    ]),
  );
  return EraAccounts.fromUr(new Ur('crypto-multi-accounts', walletCbor));
}

describe('address derivation from a linked wallet', () => {
  const accounts = buildWallet();

  it('derives the canonical first EVM address of the test seed', () => {
    // The universally published first address of the BIP-39 test mnemonic.
    expect(accounts.evm()?.deriveAddress(0)).toBe('0x9858EfFD232B4033E47d90003D41EC34EcaEda94');
  });

  it('derives the canonical BIP-84 first receive and change addresses', () => {
    const btc = accounts.btc()!;
    expect(btc.deriveAddress(0)).toBe('bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu');
    expect(btc.deriveAddress(1)).toBe('bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g');
    expect(btc.deriveAddress(0, { change: true })).toBe(
      'bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el',
    );
  });

  it('reconstructs the canonical BIP-84 zpub and the xpub @scure serializes', () => {
    const btc = accounts.btc()!;
    expect(btc.zpub()).toBe(
      'zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs',
    );
    // Independent oracle for the generic serialization: @scure/bip32's own.
    const reference = HDKey.fromMasterSeed(TEST_SEED).derive("m/84'/0'/0'").publicExtendedKey;
    expect(btc.xpub()).toBe(reference);
  });

  it('derives a well-formed Tron address', () => {
    const address = accounts.tron()!.deriveAddress(0);
    expect(address.startsWith('T')).toBe(true);
    expect(address.length).toBe(34);
  });

  it('paths and xfps follow the linked entries', () => {
    expect(accounts.evm()?.pathFor(7)).toBe("m/44'/60'/0'/0/7");
    expect(accounts.btc()?.changePath(3)).toBe("m/84'/0'/0'/1/3");
    expect(accounts.xfpFor("m/84'/0'/0'")).toBe('12345678');
    expect(() => accounts.xfpFor("m/49'/0'/0'")).toThrowError(EraSdkError);
  });

  it('refuses a wallet export with no derivable accounts', () => {
    const empty = cborEncode(
      cbMap([
        [1, cbUint(1)],
        [2, cbArray([cbMap([[9, cbText('x')]])])],
      ]),
    );
    expect(() => EraAccounts.fromUr(new Ur('crypto-multi-accounts', empty))).toThrowError(
      /no account/,
    );
  });

  it('refuses a non-wallet UR type', () => {
    try {
      EraAccounts.fromUr(new Ur('eth-signature', cborEncode(cbMap([[1, cbUint(1)]]))));
      expect.unreachable();
    } catch (e) {
      expect((e as EraSdkError).code).toBe('wrong-ur-type');
    }
  });
});
