import { describe, expect, it } from 'vitest';
import { tonAddressFromPublicKey } from '../src/accounts/derive';
import { hexToBytes } from '../src/core/bytes';

/**
 * A TON address is not a hash of the key: it is the hash of the wallet
 * CONTRACT the key would deploy, so the recipe involves the V4R2 code cell's
 * hash and depth, a data cell of 321 bits, and a StateInit cell with two refs.
 *
 * The vector is the firmware's own device-verified regression case
 * (`tests/Basic-tests/test_ton_address_gen.py`): seed
 * `8921ec62…44c9fd`, path `m/44'/607'/0'`, address
 * `UQBwluCEV9BhNqgIRETT4reunDpTDDotShNuKeTbst9Bdn8N`. The public key below is
 * that path's key, derived independently by a stdlib SLIP-0010 + RFC-8032
 * implementation that reproduces the same address end to end.
 */
const PUBLIC_KEY = hexToBytes('0d1a1f413eed4d02e7abbc5139a1e0446cd807d7692d43c294e50925782f25b2');
const ADDRESS = 'UQBwluCEV9BhNqgIRETT4reunDpTDDotShNuKeTbst9Bdn8N';

describe('tonAddressFromPublicKey', () => {
  it('matches the address the device shows for the same key', () => {
    expect(tonAddressFromPublicKey(PUBLIC_KEY)).toBe(ADDRESS);
  });

  it('is the 48-character non-bounceable friendly form by default', () => {
    const address = tonAddressFromPublicKey(PUBLIC_KEY);
    expect(address).toHaveLength(48);
    expect(address.startsWith('UQ')).toBe(true);
  });

  it('bounceable is the same account under a different tag', () => {
    const bounceable = tonAddressFromPublicKey(PUBLIC_KEY, { bounceable: true });
    expect(bounceable.startsWith('EQ')).toBe(true);
    expect(bounceable).not.toBe(ADDRESS);
    // Same 32-byte account id, different tag byte and therefore checksum.
    expect(bounceable.slice(2, 44)).toBe(ADDRESS.slice(2, 44));
  });

  it('refuses anything but a 32-byte ed25519 key', () => {
    expect(() => tonAddressFromPublicKey(PUBLIC_KEY.subarray(1))).toThrowError(
      /32-byte ed25519 key/,
    );
  });
});
