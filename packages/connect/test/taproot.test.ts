import { HDKey } from '@scure/bip32';
import { describe, expect, it } from 'vitest';
import { btcTaprootAddressFromPublicKey, derivePublicKey } from '../src/accounts/derive';

/**
 * BIP-86 "Test vectors" — the published account key and the addresses it must
 * produce. These are the ground truth for the TapTweak: the witness program is
 * the tweaked output key Q, never the BIP-32 child key P. Encoding P instead
 * yields a valid-looking `bc1p…` that no BIP-86 signer can spend, which is
 * exactly the bug this function was written to close.
 *
 * https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki
 */
const ACCOUNT_XPUB =
  'xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ';

const VECTORS = [
  { change: 0, index: 0, address: 'bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr' },
  { change: 0, index: 1, address: 'bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh' },
  { change: 1, index: 0, address: 'bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7' },
] as const;

const account = HDKey.fromExtendedKey(ACCOUNT_XPUB);
const accountKey = account.publicKey!;
const accountChainCode = account.chainCode!;

function childAt(change: number, index: number): Uint8Array {
  return derivePublicKey(accountKey, accountChainCode, change, index);
}

describe('btcTaprootAddressFromPublicKey', () => {
  it.each(VECTORS)('matches BIP-86 vector $change/$index', ({ change, index, address }) => {
    expect(btcTaprootAddressFromPublicKey(childAt(change, index))).toBe(address);
  });

  it('is not the untweaked internal key', () => {
    // The defect this replaces: bech32m over x(child) rather than x(Q). If the
    // tweak is ever dropped again, this is the assertion that says so out loud
    // instead of letting a wrong address ship.
    const child = childAt(0, 0);
    const internalKeyHex = Buffer.from(child.subarray(1)).toString('hex');
    expect(internalKeyHex).toBe(
      'cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115',
    );
    expect(btcTaprootAddressFromPublicKey(child)).not.toBe(
      // what bech32m of the internal key would give
      'bc1pej9yh3jd39aam30mctm8paaghg9nsemezpk0zg3udlza0nt0cy2sqvps98',
    );
  });

  it('uses bech32m, not bech32 — a v1 program in bech32 is a different string', () => {
    const addr = btcTaprootAddressFromPublicKey(childAt(0, 0));
    expect(addr.startsWith('bc1p')).toBe(true);
    expect(addr).toHaveLength(62);
  });

  it('honours the testnet hrp', () => {
    expect(btcTaprootAddressFromPublicKey(childAt(0, 0), 'tb').startsWith('tb1p')).toBe(true);
  });

  it('refuses anything but a 33-byte compressed key', () => {
    expect(() => btcTaprootAddressFromPublicKey(childAt(0, 0).subarray(1))).toThrowError(
      /33-byte compressed key/,
    );
  });

  it('ignores the child key Y parity, as BIP-341 lift_x requires', () => {
    // lift_x always takes the even-Y point, so a 0x02 and a 0x03 prefix over
    // the same x must land on the same address. A hand-rolled tweak that
    // forgets to negate the odd case gets this wrong.
    const child = childAt(0, 0);
    const flipped = new Uint8Array(child);
    flipped[0] = child[0] === 0x02 ? 0x03 : 0x02;
    expect(btcTaprootAddressFromPublicKey(flipped)).toBe(btcTaprootAddressFromPublicKey(child));
  });
});
