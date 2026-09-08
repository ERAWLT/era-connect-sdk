import { HDKey } from '@scure/bip32';
import { bech32 } from '@scure/base';
import { describe, expect, it } from 'vitest';
import { ethermintAddressFromPublicKey, evmAddressFromPublicKey } from '../src/accounts/derive';
import { cborEncode } from '../src/cbor/encode';
import { cbArray, cbBool, cbBytes, cbMap, cbTag, cbUint } from '../src/cbor/model';
import { bytesToHex, hexToBytes } from '../src/core/bytes';
import { COSMOS_CHAINS, cosmosChain, EraAccounts, Ur } from '../src/index';

/**
 * The Cosmos family, transcribed from the firmware's `CosmosCoinInfo` table.
 * Twenty-four zones share SLIP-44 118, so the export carries ONE key for all of
 * them and only the HRP differs — which is why the registry is what a caller
 * enumerates, never the export's entries.
 *
 * Address expectations come from the standalone stdlib oracle that reproduces
 * the published BIP-44 / BIP-84 Bitcoin vectors for this seed byte-for-byte.
 */
const TEST_SEED = hexToBytes(
  '5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4',
);
const master = HDKey.fromMasterSeed(TEST_SEED);

function levels(list: [number, boolean][]) {
  return cbArray(list.flatMap(([i, h]) => [cbUint(i), cbBool(h)]));
}

function entryAt(path: string, list: [number, boolean][], xfp: number) {
  const node = master.derive(path);
  return cbMap([
    [3, cbBytes(node.publicKey!)],
    [4, cbBytes(node.chainCode!)],
    [6, cbTag(304, cbMap([[1, levels(list)], [2, cbUint(xfp)]]))],
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
            entryAt("m/44'/118'/0'", [[44, true], [118, true], [0, true]], 0x11111111),
            entryAt("m/44'/459'/0'", [[44, true], [459, true], [0, true]], 0x22222222),
            entryAt("m/44'/60'/0'", [[44, true], [60, true], [0, true]], 0x33333333),
          ]),
        ],
      ]),
    ),
  ),
);

describe('the Cosmos chain registry', () => {
  it('carries every zone the firmware declares, with unique ids', () => {
    expect(COSMOS_CHAINS).toHaveLength(33);
    expect(new Set(COSMOS_CHAINS.map((c) => c.id)).size).toBe(33);
  });

  it('puts most zones on the shared 118 path', () => {
    // 33 zones: 24 share SLIP-44 118, three are Ethermint on 60, and six have
    // their own coin type (Secret 529, Cronos 394, Kava 459, Terra 330,
    // THORChain 931, Terra Classic 330 — which shares Terra's).
    expect(COSMOS_CHAINS.filter((c) => c.slip44 === 118)).toHaveLength(24);
    expect(COSMOS_CHAINS.filter((c) => c.ethermint)).toHaveLength(3);
    expect(
      COSMOS_CHAINS.filter((c) => c.slip44 !== 118 && !c.ethermint),
    ).toHaveLength(6);
  });

  it('marks exactly Injective, Evmos and Dymension as ethermint', () => {
    expect(COSMOS_CHAINS.filter((c) => c.ethermint).map((c) => c.id)).toEqual([
      'injective',
      'evmos',
      'dymension',
    ]);
  });

  it('names the zone in the error when an id is unknown', () => {
    expect(() => cosmosChain('nope')).toThrowError(/unknown Cosmos chain "nope"/);
  });
});

describe('Cosmos addresses', () => {
  it('gives every 118 zone the same key under its own hrp', () => {
    const view = wallet.cosmos()!;
    expect(view.accountPath).toBe("m/44'/118'/0'");
    expect(view.deriveAddress(0, { chain: 'cosmos' })).toBe(
      'cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4',
    );
    expect(view.deriveAddress(0, { chain: 'osmosis' })).toBe(
      'osmo19rl4cm2hmr8afy4kldpxz3fka4jguq0a5m7df8',
    );
    expect(view.deriveAddress(0, { chain: 'celestia' })).toBe(
      'celestia19rl4cm2hmr8afy4kldpxz3fka4jguq0ad2ud9c',
    );
    expect(view.deriveAddress(1, { chain: 'cosmos' })).toBe(
      'cosmos1jrkmdcwgq94uaamx6zax2luewlhf7u4kucx3kz',
    );
  });

  it('resolves a non-118 zone to its own coin type', () => {
    const kava = wallet.cosmos('kava')!;
    expect(kava.accountPath).toBe("m/44'/459'/0'");
    expect(kava.chain?.hrp).toBe('kava');
    // A bound view needs no options at all.
    expect(kava.deriveAddress(0)).toBe('kava1fzgm3840v4xwme059mfnx9rc5qgzl0enq7qgac');
  });

  it('answers undefined for a zone the export does not carry', () => {
    expect(wallet.cosmos('thorchain')).toBeUndefined();
    expect(wallet.cosmos('secret')).toBeUndefined();
  });

  it('lists only the zones this export can actually serve', () => {
    const ids = wallet.cosmosChains().map((c) => c.id);
    expect(ids).toContain('cosmos');
    expect(ids).toContain('osmosis');
    expect(ids).toContain('kava');
    expect(ids).toContain('injective');
    expect(ids).not.toContain('thorchain');
    // 24 zones on the shared 118 key, Kava on its own 459, three ethermint
    // served by the EVM account.
    expect(ids).toHaveLength(28);
  });

  it('refuses to guess an hrp when no zone is named', () => {
    expect(() => wallet.cosmos()!.deriveAddress(0)).toThrowError(/name a Cosmos zone/);
  });
});

describe('Ethermint zones are EVM keys wearing a Cosmos coat', () => {
  it('is served by the EVM account, not a Cosmos one', () => {
    const inj = wallet.cosmos('injective')!;
    expect(inj.accountPath).toBe("m/44'/60'/0'");
  });

  it('encodes the ETHEREUM address bytes under the zone hrp', () => {
    const inj = wallet.cosmos('injective')!;
    const address = inj.deriveAddress(0);
    expect(address.startsWith('inj1')).toBe(true);

    // The proof that the recipe is keccak and not hash160: the bech32 payload
    // must be exactly the 20 bytes of the EVM address for the same key, which
    // published vectors already pin.
    const decoded = bech32.fromWords(bech32.decode(address as `${string}1${string}`).words);
    const evm = wallet.evm()!.deriveAddress(0).slice(2).toLowerCase();
    expect(bytesToHex(new Uint8Array(decoded))).toBe(evm);
  });

  it('a raw prefix always means the classic recipe, never ethermint', () => {
    // `prefix` is the escape hatch for zones the registry does not carry, so
    // it must not silently inherit a bound zone's hashing.
    const inj = wallet.cosmos('injective')!;
    expect(inj.deriveAddress(0, { prefix: 'inj' })).not.toBe(inj.deriveAddress(0));
  });

  it('the standalone encoder agrees with the view', () => {
    const key = master.derive("m/44'/60'/0'/0/0").publicKey!;
    expect(ethermintAddressFromPublicKey(key, 'inj')).toBe(wallet.cosmos('injective')!.deriveAddress(0));
    expect(evmAddressFromPublicKey(key)).toBe(wallet.evm()!.deriveAddress(0));
  });
});
