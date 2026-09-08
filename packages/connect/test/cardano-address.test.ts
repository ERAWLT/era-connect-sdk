import { blake2b } from '@noble/hashes/blake2b';
import { bech32 } from '@scure/base';
import { describe, expect, it } from 'vitest';
import { cardanoBaseAddress } from '../src/accounts/derive';
import { cborEncode } from '../src/cbor/encode';
import { cbArray, cbBool, cbBytes, cbMap, cbTag, cbUint } from '../src/cbor/model';
import { concatBytes } from '../src/core/bytes';
import { EraAccounts, Ur } from '../src/index';

/**
 * A Shelley BASE address joins two keys — payment and stake — so it commits to
 * both. The layout is `header(1) || blake2b224(payment) || blake2b224(stake)`
 * with header `0x01` (type 0, mainnet), bech32 under `addr`, exactly as the
 * firmware's `CardanoAddress.cpp` builds it.
 *
 * The expectations here are ASSEMBLED FROM PRIMITIVES rather than restated, so
 * a change to the header byte, the hash length, the key order or the checksum
 * variant fails even though the derived keys come from code tested elsewhere.
 */
function levels(list: [number, boolean][]) {
  return cbArray(list.flatMap(([i, h]) => [cbUint(i), cbBool(h)]));
}

const key = new Uint8Array(32).fill(0x11);
const chainCode = new Uint8Array(32).fill(0x22);

const wallet = EraAccounts.fromUr(
  new Ur(
    'crypto-multi-accounts',
    cborEncode(
      cbMap([
        [1, cbUint(0x12345678)],
        [
          2,
          cbArray([
            cbMap([
              [3, cbBytes(key)],
              [4, cbBytes(chainCode)],
              [
                6,
                cbTag(
                  304,
                  cbMap([
                    [
                      1,
                      levels([
                        [1852, true],
                        [1815, true],
                        [0, true],
                      ]),
                    ],
                    [2, cbUint(0x33333333)],
                  ]),
                ),
              ],
            ]),
          ]),
        ],
      ]),
    ),
  ),
);

const ada = wallet.cardano()!;

/** The address as the spec spells it, built here from byte primitives. */
function expectedAddress(payment: Uint8Array, stake: Uint8Array): string {
  const payload = concatBytes(
    new Uint8Array([0x01]),
    blake2b(payment, { dkLen: 28 }),
    blake2b(stake, { dkLen: 28 }),
  );
  return bech32.encode('addr', bech32.toWords(payload), 200);
}

describe('Cardano Shelley base addresses', () => {
  it('joins the payment key to the stake key at 2/0', () => {
    expect(ada.deriveAddress(0)).toBe(expectedAddress(ada.deriveKey(0, 0), ada.deriveKey(2, 0)));
  });

  it('is 57 bytes under the addr hrp', () => {
    const address = ada.deriveAddress(0);
    expect(address.startsWith('addr1')).toBe(true);
    const words = bech32.decode(address as `${string}1${string}`, 200).words;
    const bytes = bech32.fromWords(words);
    expect(bytes).toHaveLength(57);
    expect(bytes[0]).toBe(0x01);
  });

  it('change uses role 1 and the SAME stake key', () => {
    const change = ada.deriveAddress(0, { change: true });
    expect(change).not.toBe(ada.deriveAddress(0));
    expect(change).toBe(expectedAddress(ada.deriveKey(1, 0), ada.deriveKey(2, 0)));
  });

  it('walks the receive chain', () => {
    expect(ada.deriveAddress(1)).not.toBe(ada.deriveAddress(0));
    expect(ada.deriveAddress(1)).toBe(expectedAddress(ada.deriveKey(0, 1), ada.deriveKey(2, 0)));
  });

  it('refuses keys that are not 32 bytes', () => {
    expect(() => cardanoBaseAddress(key.subarray(1), key)).toThrowError(/two 32-byte keys/);
  });

  it('an enterprise-style single-key address is NOT what this builds', () => {
    // Both halves matter: swapping them must change the address, or the stake
    // key is not really committed to.
    expect(cardanoBaseAddress(key, chainCode)).not.toBe(cardanoBaseAddress(chainCode, key));
  });
});
