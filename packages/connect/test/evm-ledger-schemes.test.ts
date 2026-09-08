import { HDKey } from '@scure/bip32';
import { describe, expect, it } from 'vitest';
import { derivePublicKeyChild, evmAddressFromPublicKey } from '../src/accounts/derive';
import { cborEncode } from '../src/cbor/encode';
import { cbArray, cbBool, cbBytes, cbMap, cbTag, cbText, cbUint } from '../src/cbor/model';
import { hexToBytes } from '../src/core/bytes';
import { EraAccounts, Ur } from '../src/index';

/**
 * The device exports three EVM derivations and `evm()` answers only the
 * standard one, so the other two were invisible. They are not
 * interchangeable: Ledger Live ships fully derived LEAVES (one key per
 * account, nothing to derive), while Ledger legacy is an account whose
 * addresses sit ONE level below it rather than two.
 */
const TEST_SEED = hexToBytes(
  '5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4',
);
const master = HDKey.fromMasterSeed(TEST_SEED);

function levels(list: [number, boolean][]) {
  return cbArray(list.flatMap(([i, h]) => [cbUint(i), cbBool(h)]));
}

function entry(
  path: string,
  list: [number, boolean][],
  options?: { note?: string; chainCode?: boolean },
) {
  const node = master.derive(path);
  const items: [number, ReturnType<typeof cbUint>][] = [[3, cbBytes(node.publicKey!)]];
  if (options?.chainCode !== false) items.push([4, cbBytes(node.chainCode!)]);
  items.push([6, cbTag(304, cbMap([[1, levels(list)], [2, cbUint(0x11111111)]]))]);
  if (options?.note) items.push([10, cbText(options.note)]);
  return cbMap(items);
}

const acct: [number, boolean][] = [[44, true], [60, true], [0, true]];
const live0: [number, boolean][] = [[44, true], [60, true], [0, true], [0, false], [0, false]];
const live1: [number, boolean][] = [[44, true], [60, true], [1, true], [0, false], [0, false]];

const wallet = EraAccounts.fromUr(
  new Ur(
    'crypto-multi-accounts',
    cborEncode(
      cbMap([
        [1, cbUint(master.fingerprint >>> 0)],
        [
          2,
          cbArray([
            entry("m/44'/60'/0'", acct, { note: 'account.standard' }),
            entry("m/44'/60'/0'", acct, { note: 'account.ledger_legacy' }),
            entry("m/44'/60'/0'/0/0", live0),
            entry("m/44'/60'/1'/0/0", live1),
            // Ethermint: same path shape as a Ledger Live leaf, but no chain code.
            entry("m/44'/60'/0'/0/0", live0, { chainCode: false }),
          ]),
        ],
      ]),
    ),
  ),
);

describe('the two Ledger EVM schemes', () => {
  it('evm() still answers the standard account', () => {
    expect(wallet.evm()!.accountPath).toBe("m/44'/60'/0'");
    expect(wallet.evm()!.deriveAddress(0)).toBe(
      evmAddressFromPublicKey(master.derive("m/44'/60'/0'/0/0").publicKey!),
    );
  });

  it('ledger legacy derives ONE level below the account, not two', () => {
    const legacy = wallet.evmLedgerLegacy()!;
    expect(legacy.scheme).toBe('ledger-legacy');
    expect(legacy.path).toBe("m/44'/60'/0'");
    const account = master.derive("m/44'/60'/0'");
    expect(legacy.deriveAddress(3)).toBe(
      evmAddressFromPublicKey(
        derivePublicKeyChild(account.publicKey!, account.chainCode!, 3),
      ),
    );
    // ...which is a different address from the standard scheme's index 3.
    expect(legacy.deriveAddress(3)).not.toBe(wallet.evm()!.deriveAddress(3));
  });

  it('ledger live entries are already-derived leaves, in export order', () => {
    const live = wallet.evmLedgerLive();
    expect(live.map((v) => v.path)).toEqual(["m/44'/60'/0'/0/0", "m/44'/60'/1'/0/0"]);
    expect(live[0]!.deriveAddress()).toBe(
      evmAddressFromPublicKey(master.derive("m/44'/60'/0'/0/0").publicKey!),
    );
  });

  it('the chain-code-less Ethermint leaf is not mistaken for Ledger Live', () => {
    // Five entries share `m/44'/60'`; only two are Ledger Live leaves.
    expect(wallet.evmLedgerLive()).toHaveLength(2);
  });

  it('a Ledger Live entry refuses to pretend it can derive further', () => {
    expect(() => wallet.evmLedgerLive()[0]!.deriveAddress(1)).toThrowError(
      /ask for another entry, not another index/,
    );
  });
});
