import { ripemd160 } from '@noble/hashes/ripemd160';
import { sha256 } from '@noble/hashes/sha2';
import { base58xrp, bech32 } from '@scure/base';
import { HDKey } from '@scure/bip32';
import { describe, expect, it } from 'vitest';
import { xrpAddressFromPublicKey } from '../src/accounts/derive';
import { cborEncode } from '../src/cbor/encode';
import type { CborValue } from '../src/cbor/model';
import { cbArray, cbBool, cbBytes, cbMap, cbTag, cbText, cbUint } from '../src/cbor/model';
import { hexToBytes } from '../src/core/bytes';
import type { AccountChain, BtcPurpose, EraErrorCode, RawAccountEntry } from '../src/index';
import {
  BtcAccountView,
  EraAccounts,
  EraSdkError,
  formatPath,
  parseMultiAccountsUr,
  parsePath,
  Ur,
} from '../src/index';

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
  xfp = 0x12345678,
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
          [2, cbUint(xfp)],
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
  const cosmos = master.derive("m/44'/118'/0'");
  const xrp = master.derive("m/44'/144'/0'");
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
          accountEntry(cosmos, [
            [44, true],
            [118, true],
            [0, true],
          ]),
          accountEntry(xrp, [
            [44, true],
            [144, true],
            [0, true],
          ]),
        ]),
      ],
      [3, cbText('ERA Wallet')],
    ]),
  );
  return EraAccounts.fromUr(new Ur('crypto-multi-accounts', walletCbor));
}

/** The oracle's own hash160 — never the SDK's. */
function refHash160(data: Uint8Array): Uint8Array {
  return ripemd160(sha256(data));
}

/** Child key straight from the seed, bypassing everything under test. */
function refChildKey(accountPath: string, index: number): Uint8Array {
  return HDKey.fromMasterSeed(TEST_SEED).derive(`${accountPath}/0/${index}`).publicKey!;
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

  it('derives Cosmos addresses under a caller-supplied zone prefix', () => {
    const cosmos = accounts.cosmos()!;
    // Independent oracle: seed -> @scure/bip32 -> hash160 -> bech32, no SDK.
    const words = bech32.toWords(refHash160(refChildKey("m/44'/118'/0'", 0)));
    expect(cosmos.deriveAddress(0, { prefix: 'cosmos' })).toBe(bech32.encode('cosmos', words));
    expect(cosmos.deriveAddress(0, { prefix: 'osmo' })).toBe(bech32.encode('osmo', words));
    expect(cosmos.deriveAddress(3, { prefix: 'celestia' })).toBe(
      bech32.encode('celestia', bech32.toWords(refHash160(refChildKey("m/44'/118'/0'", 3)))),
    );
    // Same key under two HRPs: the same 20 bytes, a checksum that follows the prefix.
    const payloadOf = (address: string) =>
      bech32.fromWords(bech32.decode(address as `${string}1${string}`).words);
    expect(payloadOf(cosmos.deriveAddress(0, { prefix: 'osmo' }))).toEqual(
      payloadOf(cosmos.deriveAddress(0, { prefix: 'cosmos' })),
    );
    expect(payloadOf(cosmos.deriveAddress(0, { prefix: 'cosmos' })).length).toBe(20);
    expect(cosmos.derivePublicKey(0)).toEqual(refChildKey("m/44'/118'/0'", 0));
  });

  it('derives XRP classic addresses', () => {
    const xrp = accounts.xrp()!;
    // Independent oracle: base58check over XRPL's own alphabet, built here.
    const payload = new Uint8Array([0x00, ...refHash160(refChildKey("m/44'/144'/0'", 0))]);
    const expected = base58xrp.encode(
      new Uint8Array([...payload, ...sha256(sha256(payload)).slice(0, 4)]),
    );
    const address = xrp.deriveAddress(0);
    expect(address).toBe(expected);
    expect(address.startsWith('r')).toBe(true);
    expect(xrp.derivePublicKey(0)).toEqual(refChildKey("m/44'/144'/0'", 0));
  });

  it('matches the published XRPL address-encoding vectors', () => {
    // XRPL docs worked example (Ed25519 key, 0xED-prefixed).
    expect(
      xrpAddressFromPublicKey(
        hexToBytes('ED9434799226374926EDA3B54B1B461B4ABF7237962EAE18528FEA67595397FA32'),
      ),
    ).toBe('rDTXLQ7ZKZVKz33zJbHjgVShjsBnqMBhmN');
    // The genesis ("masterpassphrase") secp256k1 key: the shape this SDK derives.
    expect(
      xrpAddressFromPublicKey(
        hexToBytes('0330E7FC9D56BB25D6893BA3F317AE5BCF33B3291BD63DB32654A313222F7FD020'),
      ),
    ).toBe('rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh');
  });

  it('classifies the Cosmos and XRP entries instead of shrugging', () => {
    const byPath = new Map(accounts.keys.map((k) => [k.path, k.chain]));
    expect(byPath.get("m/44'/118'/0'")).toBe('cosmos');
    expect(byPath.get("m/44'/144'/0'")).toBe('xrp');
    expect(accounts.keys.some((k) => k.chain === 'unknown')).toBe(false);
  });

  it('paths and xfps follow the linked entries', () => {
    expect(accounts.evm()?.pathFor(7)).toBe("m/44'/60'/0'/0/7");
    expect(accounts.btc()?.changePath(3)).toBe("m/84'/0'/0'/1/3");
    expect(accounts.cosmos()?.accountPath).toBe("m/44'/118'/0'");
    expect(accounts.cosmos()?.pathFor(2)).toBe("m/44'/118'/0'/0/2");
    expect(accounts.cosmos()?.xfp).toBe('12345678');
    expect(accounts.xrp()?.accountPath).toBe("m/44'/144'/0'");
    expect(accounts.xrp()?.signingPath).toBe("m/44'/144'/0'/0/0");
    expect(accounts.xrp()?.pathFor(5)).toBe("m/44'/144'/0'/0/5");
    expect(accounts.xrp()?.xfp).toBe('12345678');
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
// ---------------------------------------------------------------------------
// Bitcoin: the network SELECTS the account
// ---------------------------------------------------------------------------
//
// The exact addresses and extended keys of every purpose on both networks
// live in the SHARED fixture `test/fixtures/accounts-testnet.json` and are
// asserted by `accounts-testnet-parity.test.ts`. What stays here is the
// behaviour that fixture cannot express: which entry is picked, which asks
// are refused outright, and what a coin-type-1' path classifies as.

const BTC_PURPOSES: readonly BtcPurpose[] = [84, 44, 49, 86];

/**
 * The out-of-set purposes an unchecked caller can ask for. The export the
 * bound is tested against CARRIES an account at every one of them except
 * `-1`, on both networks, so widening the bound by a single purpose selects a
 * real view and fails the test: `undefined` is the guard talking and not an
 * empty search.
 *
 * `-1` is the deliberate exception. A BIP-32 path level is unsigned, so no
 * export can express that purpose and no widening of the bound could return a
 * view for it — it stands for the raw garbage a JavaScript caller can pass,
 * and it is the one member of this list a carried entry cannot back.
 */
const FOREIGN_PURPOSES: readonly number[] = [-1, 0, 1, 43, 45, 48, 60, 85, 87, 1852];

/** The nine of those an export can actually carry an account at. */
const CARRIED_FOREIGN_PURPOSES: readonly number[] = FOREIGN_PURPOSES.filter((p) => p >= 0);

/**
 * The xfp given to the entry for `purpose` on each network: `aa0000xx` on
 * mainnet, `bb0000xx` on testnet, where `xx` is the purpose in hex (84 →
 * `54`). One glance at a view's xfp then says which entry it selected.
 */
function xfpOf(purpose: number, coinType: 0 | 1): number {
  return (coinType === 0 ? 0xaa000000 : 0xbb000000) + purpose;
}

function xfpHexOf(purpose: number, coinType: 0 | 1): string {
  return xfpOf(purpose, coinType).toString(16).padStart(8, '0');
}

/** One entry at exactly these levels — hardened-ness included, since selection checks it. */
function btcEntry(levels: [number, boolean][], xfp: number): CborValue {
  const path = `m/${levels.map(([index, hardened]) => `${index}${hardened ? "'" : ''}`).join('/')}`;
  return accountEntry(HDKey.fromMasterSeed(TEST_SEED).derive(path), levels, [], xfp);
}

/**
 * One entry at exactly `levels`, carrying the key derived at `derivePath`
 * truncated to `keyLength` bytes — 32 for the Ed25519 chains, whose selectors
 * check the length before anything else, so a 33-byte key would make a
 * classification test pass for the wrong reason.
 */
function entryWithKeyLength(
  derivePath: string,
  levels: [number, boolean][],
  keyLength: 32 | 33,
  xfp = 0x12345678,
): CborValue {
  const node = HDKey.fromMasterSeed(TEST_SEED).derive(derivePath);
  const publicKey = keyLength === 33 ? node.publicKey! : node.publicKey!.slice(1);
  return cbMap([
    [3, cbBytes(publicKey)],
    [4, cbBytes(node.chainCode!)],
    [
      6,
      cbTag(
        304,
        cbMap([
          [1, pathComponents(levels)],
          [2, cbUint(xfp)],
        ]),
      ),
    ],
    [8, cbUint(node.parentFingerprint >>> 0)],
  ]);
}

/** `m/<purpose>'/<coinType>'/0'` for all four BIP purposes. */
function btcAccountEntries(coinType: 0 | 1): CborValue[] {
  return BTC_PURPOSES.map((purpose) =>
    btcEntry(
      [
        [purpose, true],
        [coinType, true],
        [0, true],
      ],
      xfpOf(purpose, coinType),
    ),
  );
}

/**
 * A wallet export carrying exactly `entries`, in that order. The UR is built
 * with this SDK's own encoder — the wallet is test INPUT and its encoding is
 * pinned by the UR vector tests.
 */
function walletUr(entries: CborValue[]): Ur {
  const master = HDKey.fromMasterSeed(TEST_SEED);
  return new Ur(
    'crypto-multi-accounts',
    cborEncode(
      cbMap([
        [1, cbUint(master.fingerprint >>> 0)],
        [2, cbArray(entries)],
        [3, cbText('ERA Wallet')],
      ]),
    ),
  );
}

function walletOf(entries: CborValue[]): EraAccounts {
  return EraAccounts.fromUr(walletUr(entries));
}

/** The raw entry at `accountPath` — the material a caller of the view's constructor holds. */
function rawEntryAt(entries: CborValue[], accountPath: string): RawAccountEntry {
  const entry = parseMultiAccountsUr(walletUr(entries)).entries.find(
    (e) => formatPath([...e.path]) === accountPath,
  );
  if (!entry) throw new Error(`no entry at ${accountPath}`);
  return entry;
}

/** What a JavaScript caller does: an unchecked number where the type says otherwise. */
function askPurpose(
  accounts: EraAccounts,
  purpose: number,
  testnet = false,
): BtcAccountView | undefined {
  return accounts.btc({ purpose: purpose as BtcPurpose, testnet });
}

/**
 * Pin a refusal on BOTH halves: the `code` an integrator branches on, and the
 * message a human reads. Pinning one alone lets the other change unnoticed.
 */
function expectRefusal(fn: () => unknown, code: EraErrorCode, message: string): void {
  let caught: unknown;
  try {
    fn();
  } catch (e) {
    caught = e;
  }
  expect(caught).toBeInstanceOf(EraSdkError);
  const error = caught as EraSdkError;
  expect(error.code).toBe(code);
  expect(error.message).toBe(message);
}

const TAPROOT_REFUSAL =
  'taproot addresses need the BIP-341 output-key tweak; derive them from xpub() with your Bitcoin library';
const ZPUB_REFUSAL = 'zpub is the SLIP-132 form of the BIP-84 account only';

describe('Bitcoin network selection', () => {
  // The testnet entries come FIRST on purpose: a selector that returned "the
  // first Bitcoin-looking entry" would hand every mainnet caller a testnet
  // account, and this ordering is what catches that.
  const bothEntries = [...btcAccountEntries(1), ...btcAccountEntries(0)];
  const both = walletOf(bothEntries);

  it('selects the coin-type-0 account for every purpose on a both-networks export', () => {
    for (const purpose of BTC_PURPOSES) {
      const view = both.btc({ purpose })!;
      expect(view.accountPath).toBe(`m/${purpose}'/0'/0'`);
      expect(view.purpose).toBe(purpose);
      expect(view.xfp).toBe(xfpHexOf(purpose, 0));
    }
  });

  it('selects the coin-type-1 account for every purpose on a both-networks export', () => {
    for (const purpose of BTC_PURPOSES) {
      const view = both.btc({ testnet: true, purpose })!;
      expect(view.accountPath).toBe(`m/${purpose}'/1'/0'`);
      expect(view.purpose).toBe(purpose);
      expect(view.xfp).toBe(xfpHexOf(purpose, 1));
    }
    // The child paths come from the entry, so they follow the network for free.
    const btc84 = both.btc({ testnet: true })!;
    expect(btc84.receivePath(0)).toBe("m/84'/1'/0'/0/0");
    expect(btc84.changePath(3)).toBe("m/84'/1'/0'/1/3");
  });

  it('never lets the two networks share an answer', () => {
    for (const purpose of BTC_PURPOSES) {
      const mainnet = both.btc({ purpose })!;
      const testnet = both.btc({ testnet: true, purpose })!;
      expect(testnet.accountPath).not.toBe(mainnet.accountPath);
      expect(testnet.xfp).not.toBe(mainnet.xfp);
      expect(testnet.xpub()).not.toBe(mainnet.xpub());
    }
  });

  // A `crypto-keypath` admits any path from one level up, so an export can
  // carry `m/84'` — and the selection predicate walks EVERY entry looking for
  // its match, this one included. Its `p0 !== undefined && p1 !== undefined`
  // clause is what keeps that a non-event: without it the predicate reads
  // `.hardened` off `undefined` and a public method throws an untyped host
  // TypeError, where every other refusal on this path is an `EraSdkError` a
  // caller can branch on.
  it('walks past a one-level entry to the real account, without throwing', () => {
    const short = walletOf([btcEntry([[84, true]], 0xcc000054), ...btcAccountEntries(0)]);
    expect(short.keys[0]!.path).toBe("m/84'");

    expect(() => short.btc()).not.toThrow();
    expect(short.btc()!.accountPath).toBe("m/84'/0'/0'");
    expect(short.btc()!.xfp).toBe(xfpHexOf(84, 0));

    // The same walk on the branch that finds nothing: still a value, still
    // not an exception.
    expect(() => short.btc({ testnet: true })).not.toThrow();
    expect(short.btc({ testnet: true })).toBeUndefined();
  });

  // The bound used to come for free from `classify(e.path) === 'btc'`, which
  // admitted only the four BIP purposes. Selecting on a bare number lost it,
  // and `BtcPurpose` is erased at runtime: a JavaScript caller, or a cast,
  // reaches the same method.
  describe('the purpose is bounded to the four BIP values', () => {
    // An export that really CARRIES an account at every enumerated purpose,
    // on BOTH networks, so `undefined` is the guard talking and not an empty
    // search. Hand-picking two or three of them left the rest of the loop
    // below asserting nothing: widening the bound to a purpose no entry sits
    // at returns `undefined` either way.
    const carryingEntries = [
      ...CARRIED_FOREIGN_PURPOSES.flatMap((purpose) => [
        btcEntry(
          [
            [purpose, true],
            [0, true],
            [0, true],
          ],
          xfpOf(purpose, 0),
        ),
        btcEntry(
          [
            [purpose, true],
            [1, true],
            [0, true],
          ],
          xfpOf(purpose, 1),
        ),
      ]),
      ...btcAccountEntries(0),
      ...btcAccountEntries(1),
    ];
    const carrying = walletOf(carryingEntries);

    it('carries an account at every out-of-set purpose it asks for', () => {
      const paths = carrying.keys.map((k) => k.path);
      for (const purpose of CARRIED_FOREIGN_PURPOSES) {
        for (const coinType of [0, 1] as const) {
          const path = `m/${purpose}'/${coinType}'/0'`;
          expect(paths, path).toContain(path);
          // Addressable by name whatever it classifies as, and with the xfp
          // the entry was built with — so a view that DID come back could be
          // told apart from a coincidence.
          expect(carrying.xfpFor(path), path).toBe(xfpHexOf(purpose, coinType));
        }
      }
      // The one member of the list no export can back, and why.
      expect(FOREIGN_PURPOSES.filter((purpose) => purpose < 0)).toEqual([-1]);
      expect(CARRIED_FOREIGN_PURPOSES.length).toBe(FOREIGN_PURPOSES.length - 1);
    });

    it('returns undefined for every purpose outside {44, 49, 84, 86}', () => {
      for (const purpose of FOREIGN_PURPOSES) {
        expect(askPurpose(carrying, purpose)).toBeUndefined();
        expect(askPurpose(carrying, purpose, true)).toBeUndefined();
      }
    });

    it('still resolves the four supported purposes on both networks', () => {
      for (const purpose of BTC_PURPOSES) {
        expect(carrying.btc({ purpose })!.accountPath).toBe(`m/${purpose}'/0'/0'`);
        expect(carrying.btc({ testnet: true, purpose })!.accountPath).toBe(`m/${purpose}'/1'/0'`);
      }
    });
  });

  // A `crypto-keypath` can express SOFT levels, and an export is hostile
  // input. Without the hardened-ness clause an entry at m/84'/1/0' would be
  // served as a Bitcoin testnet account — and it is a different key entirely.
  describe('the first two levels must be hardened', () => {
    it('a soft coin type is not a network', () => {
      const soft = walletOf([
        btcEntry(
          [
            [84, true],
            [1, false],
            [0, true],
          ],
          xfpOf(84, 1),
        ),
        btcEntry(
          [
            [84, true],
            [0, false],
            [0, true],
          ],
          xfpOf(84, 0),
        ),
      ]);
      expect(soft.keys.map((k) => k.path)).toEqual(["m/84'/1/0'", "m/84'/0/0'"]);
      expect(soft.btc({ testnet: true })).toBeUndefined();
      expect(soft.btc()).toBeUndefined();
    });

    it('a soft purpose is not a script type', () => {
      const soft = walletOf([
        btcEntry(
          [
            [84, false],
            [1, true],
            [0, true],
          ],
          xfpOf(84, 1),
        ),
        btcEntry(
          [
            [84, false],
            [0, true],
            [0, true],
          ],
          xfpOf(84, 0),
        ),
      ]);
      expect(soft.keys.map((k) => k.path)).toEqual(["m/84/1'/0'", "m/84/0'/0'"]);
      expect(soft.btc({ testnet: true })).toBeUndefined();
      expect(soft.btc()).toBeUndefined();
    });

    it('the same levels, hardened, do resolve', () => {
      const hard = walletOf([
        btcEntry(
          [
            [84, true],
            [1, true],
            [0, true],
          ],
          xfpOf(84, 1),
        ),
      ]);
      expect(hard.btc({ testnet: true })!.accountPath).toBe("m/84'/1'/0'");
    });
  });

  it('returns nothing for testnet on a mainnet-only export, never the mainnet account', () => {
    const mainnetOnly = walletOf(btcAccountEntries(0));
    for (const purpose of BTC_PURPOSES) {
      expect(mainnetOnly.btc({ testnet: true, purpose })).toBeUndefined();
      // The mainnet account is still right where it was.
      expect(mainnetOnly.btc({ purpose })!.accountPath).toBe(`m/${purpose}'/0'/0'`);
    }
    // The defect this whole change exists to prevent: the MAINNET key rendered
    // under the testnet HRP — a confident wrong answer whose path, xfp and
    // extended key all stayed mainnet. Both strings below come from one and
    // the same child key, so the second is the mainnet address's own hash160
    // wearing a `tb` prefix.
    const mainnetChild = refHash160(refChildKey("m/84'/0'/0'", 0));
    const mainnetAddress = bech32.encode('bc', [0, ...bech32.toWords(mainnetChild)]);
    const mainnetKeyUnderTestnetHrp = bech32.encode('tb', [0, ...bech32.toWords(mainnetChild)]);
    expect(mainnetOnly.btc()!.deriveAddress(0)).toBe(mainnetAddress);
    expect(mainnetKeyUnderTestnetHrp).not.toBe(mainnetAddress);
    expect(mainnetOnly.btc({ testnet: true })).toBeUndefined();
  });

  it('hides a testnet-only export from btc() and resolves it under testnet: true', () => {
    const testnetOnly = walletOf(btcAccountEntries(1));
    for (const purpose of BTC_PURPOSES) {
      expect(testnetOnly.btc({ purpose })).toBeUndefined();
      const view = testnetOnly.btc({ testnet: true, purpose })!;
      expect(view.accountPath).toBe(`m/${purpose}'/1'/0'`);
      expect(view.xfp).toBe(xfpHexOf(purpose, 1));
    }
    expect(testnetOnly.btc()).toBeUndefined();
    // The path is still addressable by name, whatever it classifies as.
    expect(testnetOnly.xfpFor("m/84'/1'/0'")).toBe(xfpHexOf(84, 1));
  });

  it("classifies a coin-type-1 path as 'unknown' — it is every coin's testnet", () => {
    // SLIP-44 assigns coin type 1 to "Testnet (all coins)", so m/84'/1'/0' is
    // as much a Litecoin testnet account as a Bitcoin one (and this SDK's own
    // PsbtCoin admits ltc/doge/dash). Attribution has no caller intent to lean
    // on, so it must say nothing rather than guess; btc({ testnet: true })
    // reaches the same entry only because the caller named the chain.
    // Widening classify() would make the SDK claim a chain it cannot know.
    for (const key of walletOf(btcAccountEntries(1)).keys) {
      expect(key.chain).toBe('unknown');
    }
    const byPath = new Map(both.keys.map((k) => [k.path, k.chain]));
    expect(byPath.get("m/84'/0'/0'")).toBe('btc');
    expect(byPath.get("m/84'/1'/0'")).toBe('unknown');
  });

  it('refuses taproot addresses on both networks, by code AND message', () => {
    for (const testnet of [false, true]) {
      const view = both.btc({ testnet, purpose: 86 })!;
      expectRefusal(() => view.deriveAddress(0), 'invalid-props', TAPROOT_REFUSAL);
      expectRefusal(
        () => view.deriveAddress(0, { change: true }),
        'invalid-props',
        TAPROOT_REFUSAL,
      );
    }
  });

  it('keeps zpub a BIP-84 concept on both networks, by code AND message', () => {
    for (const testnet of [false, true]) {
      for (const purpose of [44, 49, 86] as const) {
        expectRefusal(() => both.btc({ testnet, purpose })!.zpub(), 'invalid-props', ZPUB_REFUSAL);
      }
    }
  });
});

describe('the Bitcoin view reads its network off the account it wraps', () => {
  const entries = [...btcAccountEntries(1), ...btcAccountEntries(0)];

  it('cannot be told a network the entry does not have', () => {
    // The constructor is public and this change is the one that made
    // `RawAccountEntry` and `parseMultiAccountsUr` obtainable, so this is
    // material a caller now holds. With a `testnet` boolean in the signature
    // it produced exactly the answer the selection fix removes: the mainnet
    // witness program under a `tb` HRP, with a mainnet path, xfp and tpub.
    const mainnet = new BtcAccountView(rawEntryAt(entries, "m/84'/0'/0'"), 84, xfpOf(84, 0));
    expect(mainnet.accountPath).toBe("m/84'/0'/0'");
    expect(mainnet.deriveAddress(0).startsWith('bc1')).toBe(true);
    expect(mainnet.xpub().startsWith('xpub')).toBe(true);
    expect(mainnet.zpub().startsWith('zpub')).toBe(true);

    const testnet = new BtcAccountView(rawEntryAt(entries, "m/84'/1'/0'"), 84, xfpOf(84, 1));
    expect(testnet.accountPath).toBe("m/84'/1'/0'");
    expect(testnet.deriveAddress(0).startsWith('tb1')).toBe(true);
    expect(testnet.xpub().startsWith('tpub')).toBe(true);
    expect(testnet.zpub().startsWith('vpub')).toBe(true);
  });

  it('refuses an out-of-set purpose that reached it anyway', () => {
    // `btc()` bounds the purpose, but the constructor is public and the union
    // is erased at runtime. Without a default arm the switch is exhaustive
    // over `BtcPurpose`, `tsc --noEmit` stays silent, and `deriveAddress`
    // returns `undefined` from a signature declared `: string` — which
    // reaches a QR encoder or a change output as the text "undefined".
    const view = new BtcAccountView(
      rawEntryAt(entries, "m/84'/0'/0'"),
      48 as BtcPurpose,
      xfpOf(48, 0),
    );
    expectRefusal(() => view.deriveAddress(0), 'invalid-props', 'unsupported BIP purpose 48');
    expectRefusal(
      () => view.deriveAddress(0, { change: true }),
      'invalid-props',
      'unsupported BIP purpose 48',
    );
    expectRefusal(() => view.zpub(), 'invalid-props', ZPUB_REFUSAL);
  });
});

// ---------------------------------------------------------------------------
// The view's own coin-type check
// ---------------------------------------------------------------------------
//
// Only a HARDENED level is a SLIP-44 coin type. A `crypto-keypath` can spell a
// soft level and an export is hostile input, so `m/84'/1/0'` must not be read
// as "testnet": nothing about a soft level says which network the key belongs
// to, and the view has to stay on the mainnet encoding.
//
// `btc()` never lets such an entry through — it checks hardenedness while
// SELECTING — which is exactly why the check INSIDE the view needs a pin of
// its own. Without one, dropping the `hardened` clause from the detector
// leaves the linter, `tsc` and the whole suite green, and a reader deleting it
// as "already guaranteed" has no way to find out otherwise.
describe('a coin type is a coin type only when it is hardened', () => {
  const entries = btcAccountEntries(0);

  /** The mainnet key, presented under `path` — the same material, re-pathed. */
  function viewAt(path: string): BtcAccountView {
    const entry = rawEntryAt(entries, "m/84'/0'/0'");
    return new BtcAccountView({ ...entry, path: parsePath(path) }, 84, xfpOf(84, 0));
  }

  // One key, one purpose: the apostrophe on the second level is the entire
  // difference between these two cases.
  const MAINNET_ADDRESS_0 = 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu';
  // The SAME witness program under the testnet HRP — an address on a chain
  // whose coins this account will never hold.
  const TESTNET_ADDRESS_0 = 'tb1qcr8te4kr609gcawutmrza0j4xv80jy8zmfp6l0';

  it('reads a hardened coin type 1 as testnet', () => {
    const view = viewAt("m/84'/1'/0'");
    expect(view.accountPath).toBe("m/84'/1'/0'");
    expect(view.deriveAddress(0)).toBe(TESTNET_ADDRESS_0);
    expect(view.xpub().startsWith('tpub')).toBe(true);
    expect(view.zpub().startsWith('vpub')).toBe(true);
  });

  it('does not read a SOFT coin type 1 as testnet', () => {
    const view = viewAt("m/84'/1/0'");
    expect(view.accountPath).toBe("m/84'/1/0'");
    expect(view.deriveAddress(0)).toBe(MAINNET_ADDRESS_0);
    expect(view.deriveAddress(0)).not.toBe(TESTNET_ADDRESS_0);
    expect(view.xpub().startsWith('xpub')).toBe(true);
    expect(view.zpub().startsWith('zpub')).toBe(true);
  });

  it('does not read a soft coin type 0 as testnet either', () => {
    const view = viewAt("m/84'/0/0'");
    expect(view.deriveAddress(0)).toBe(MAINNET_ADDRESS_0);
    expect(view.xpub().startsWith('xpub')).toBe(true);
  });

  it('answers mainnet for an entry with no coin-type level at all', () => {
    const view = viewAt("m/84'");
    expect(view.accountPath).toBe("m/84'");
    expect(view.deriveAddress(0)).toBe(MAINNET_ADDRESS_0);
    expect(view.xpub().startsWith('xpub')).toBe(true);
  });

  it('keeps the base58 purposes on mainnet too, where the network is a version byte', () => {
    // 44 and 49 encode the network as a version BYTE rather than an HRP, so
    // they are a separate arm of the switch from bech32 — but they read the
    // same detector, and a detector that ignored hardenedness would flip all
    // three at once. Asserted by the address CLASS the version byte produces
    // (mainnet P2PKH `1…` / P2SH `3…`, testnet `m…`|`n…` / `2…`), which is
    // exactly what the byte decides; the exact strings for these purposes are
    // pinned against published vectors in the shared-fixture suite.
    for (const purpose of [44, 49] as const) {
      const entry = rawEntryAt(entries, "m/84'/0'/0'");
      const soft = new BtcAccountView(
        { ...entry, path: parsePath("m/84'/1/0'") },
        purpose,
        xfpOf(purpose, 0),
      );
      const hard = new BtcAccountView(
        { ...entry, path: parsePath("m/84'/1'/0'") },
        purpose,
        xfpOf(purpose, 1),
      );
      const mainnetPrefix = purpose === 44 ? /^1/ : /^3/;
      const testnetPrefix = purpose === 44 ? /^[mn]/ : /^2/;
      expect(soft.deriveAddress(0), `purpose ${purpose} soft`).toMatch(mainnetPrefix);
      expect(hard.deriveAddress(0), `purpose ${purpose} hardened`).toMatch(testnetPrefix);
      expect(soft.deriveAddress(0)).not.toBe(hard.deriveAddress(0));
    }
  });
});

// ---------------------------------------------------------------------------
// classify(): the Bitcoin condition has two halves
// ---------------------------------------------------------------------------
//
// `AccountChain.btc`'s doc comment states the contract in two parts — "all
// four purposes (44/49/84/86)" and "Coin type 0' only, on purpose ... Do not
// 'fix' classify to widen this". The coin-type half is pinned above (a
// coin-type-1' path must stay `unknown`); this is the purpose half, which was
// free to move in either direction: dropping `|| p0.index === 86` demotes
// taproot to `unknown`, and collapsing the whole condition to `p1.index === 0`
// promotes every foreign purpose at coin type 0' to `btc`.
describe('classify names exactly the four BIP purposes at coin type 0', () => {
  const wallet = walletOf([
    ...btcAccountEntries(0),
    ...CARRIED_FOREIGN_PURPOSES.map((purpose) =>
      btcEntry(
        [
          [purpose, true],
          [0, true],
          [0, true],
        ],
        xfpOf(purpose, 0),
      ),
    ),
  ]);
  const chainOf = new Map(wallet.keys.map((k) => [k.path, k.chain]));

  it("labels all four of 44'/49'/84'/86' at coin type 0' as btc", () => {
    for (const purpose of BTC_PURPOSES) {
      expect(chainOf.get(`m/${purpose}'/0'/0'`), `purpose ${purpose}`).toBe('btc');
    }
    // Every one of them, not "at least one": four entries, four labels.
    expect(BTC_PURPOSES.length).toBe(4);
  });

  it("labels coin type 0' under any OTHER purpose 'unknown'", () => {
    for (const purpose of CARRIED_FOREIGN_PURPOSES) {
      expect(chainOf.get(`m/${purpose}'/0'/0'`), `purpose ${purpose}`).toBe('unknown');
    }
    // Including the two neighbours that look most like a Bitcoin account:
    // BIP-45 multi-party and BIP-48 multisig, both of which really are
    // Bitcoin schemes — and neither of which this SDK can serve a view for.
    expect(chainOf.get("m/45'/0'/0'")).toBe('unknown');
    expect(chainOf.get("m/48'/0'/0'")).toBe('unknown');
  });
});

// ---------------------------------------------------------------------------
// classify(): the hardened gate the other nine chains rest on
// ---------------------------------------------------------------------------
//
// `btc()` has clauses and tests of its own. The other nine selectors are
// `classify(path) === <chain>` and nothing else, so the single line
// `if (!p0 || !p1 || !p0.hardened || !p1.hardened) return 'unknown'` is the
// whole of their input validation. A `crypto-keypath` can spell a soft level
// and an export is hostile input: `m/44'/60/0'` is a different key from
// `m/44'/60'/0'`, and serving it as the EVM account would put a wallet's
// addresses on a key the device never named.
describe('a soft path level is nobody', () => {
  interface GatedChain {
    readonly chain: AccountChain;
    readonly purpose: number;
    readonly coinType: number;
    /** The Ed25519 chains' selectors check the length before anything else. */
    readonly keyLength: 32 | 33;
    readonly resolves: (accounts: EraAccounts) => boolean;
  }

  const GATED: readonly GatedChain[] = [
    { chain: 'evm', purpose: 44, coinType: 60, keyLength: 33, resolves: (a) => !!a.evm() },
    { chain: 'bch', purpose: 44, coinType: 145, keyLength: 33, resolves: (a) => !!a.bch() },
    { chain: 'tron', purpose: 44, coinType: 195, keyLength: 33, resolves: (a) => !!a.tron() },
    { chain: 'cosmos', purpose: 44, coinType: 118, keyLength: 33, resolves: (a) => !!a.cosmos() },
    { chain: 'xrp', purpose: 44, coinType: 144, keyLength: 33, resolves: (a) => !!a.xrp() },
    { chain: 'ton', purpose: 44, coinType: 607, keyLength: 32, resolves: (a) => !!a.ton() },
    {
      chain: 'cardano',
      purpose: 1852,
      coinType: 1815,
      keyLength: 32,
      resolves: (a) => !!a.cardano(),
    },
    {
      chain: 'solana',
      purpose: 44,
      coinType: 501,
      keyLength: 32,
      resolves: (a) => a.solana().length > 0,
    },
    {
      chain: 'sui',
      purpose: 44,
      coinType: 784,
      keyLength: 32,
      resolves: (a) => a.sui().length > 0,
    },
  ];

  function walletFor(hardened: { purpose: boolean; coinType: boolean }): EraAccounts {
    return walletOf(
      GATED.map((spec) =>
        entryWithKeyLength(
          `m/${spec.purpose}'/${spec.coinType}'/0'`,
          [
            [spec.purpose, hardened.purpose],
            [spec.coinType, hardened.coinType],
            [0, true],
          ],
          spec.keyLength,
        ),
      ),
    );
  }

  function pathOf(spec: GatedChain, hardened: { purpose: boolean; coinType: boolean }): string {
    const p = hardened.purpose ? "'" : '';
    const c = hardened.coinType ? "'" : '';
    return `m/${spec.purpose}${p}/${spec.coinType}${c}/0'`;
  }

  const BOTH_HARDENED = { purpose: true, coinType: true };

  it('classifies and resolves all nine when both levels are hardened', () => {
    // The control. Without it the two cases below could pass because the
    // export is unreadable rather than because the gate refused it.
    const accounts = walletFor(BOTH_HARDENED);
    const chainOf = new Map(accounts.keys.map((k) => [k.path, k.chain]));
    expect(GATED.length).toBe(9);
    for (const spec of GATED) {
      expect(chainOf.get(pathOf(spec, BOTH_HARDENED)), spec.chain).toBe(spec.chain);
      expect(spec.resolves(accounts), spec.chain).toBe(true);
    }
  });

  for (const soft of [
    { label: 'a soft purpose', purpose: false, coinType: true },
    { label: 'a soft coin type', purpose: true, coinType: false },
  ]) {
    it(`${soft.label} classifies as unknown, and no selector returns it`, () => {
      const accounts = walletFor(soft);
      // The entries are all there and all addressable — only unclaimed.
      expect(accounts.keys.length).toBe(GATED.length);
      for (const spec of GATED) {
        const path = pathOf(spec, soft);
        expect(
          accounts.keys.map((k) => k.path),
          spec.chain,
        ).toContain(path);
        expect(accounts.keys.find((k) => k.path === path)?.chain, spec.chain).toBe('unknown');
        expect(spec.resolves(accounts), spec.chain).toBe(false);
      }
    });
  }
});

// ---------------------------------------------------------------------------
// The view's network detector: coin type 1 and nothing else
// ---------------------------------------------------------------------------
//
// SLIP-44 gives coin type 1 to "Testnet (all coins)", and `isTestnetAccount`'s
// own doc comment promises that every OTHER coin type a Bitcoin view can wrap
// is a mainnet account. Testing only 0 and 1 leaves `index === 1` free to
// become `index !== 0`, which is true for both — and flips every other coin
// type at once. `btc()` never selects such an entry, but `RawAccountEntry` and
// this constructor are both public, which is how a Litecoin account gets here.
describe('only coin type 1 is a testnet account', () => {
  const LITECOIN_ACCOUNT = "m/84'/2'/0'";
  const entries = [
    ...btcAccountEntries(0),
    btcEntry(
      [
        [84, true],
        [2, true],
        [0, true],
      ],
      0xcc000054,
    ),
  ];

  /** Independent oracle: the child key straight from the seed, no SDK. */
  function witnessAddresses(accountPath: string): { mainnet: string; testnet: string } {
    const words = bech32.toWords(refHash160(refChildKey(accountPath, 0)));
    return {
      mainnet: bech32.encode('bc', [0, ...words]),
      testnet: bech32.encode('tb', [0, ...words]),
    };
  }

  it('reads a coin type that is neither 0 nor 1 as mainnet', () => {
    const view = new BtcAccountView(rawEntryAt(entries, LITECOIN_ACCOUNT), 84, 0xcc000054);
    const { mainnet, testnet } = witnessAddresses(LITECOIN_ACCOUNT);
    expect(view.accountPath).toBe(LITECOIN_ACCOUNT);
    expect(view.deriveAddress(0)).toBe(mainnet);
    // The same witness program under the testnet HRP is a different string —
    // so the assertion above is not satisfied by both answers at once.
    expect(view.deriveAddress(0)).not.toBe(testnet);
    expect(view.xpub().startsWith('xpub')).toBe(true);
    expect(view.zpub().startsWith('zpub')).toBe(true);
  });

  it('still reads coin type 1 as testnet and coin type 0 as mainnet', () => {
    const testnetView = new BtcAccountView(
      { ...rawEntryAt(entries, "m/84'/0'/0'"), path: parsePath("m/84'/1'/0'") },
      84,
      xfpOf(84, 1),
    );
    expect(testnetView.deriveAddress(0).startsWith('tb1')).toBe(true);
    expect(testnetView.xpub().startsWith('tpub')).toBe(true);

    const mainnetView = new BtcAccountView(rawEntryAt(entries, "m/84'/0'/0'"), 84, xfpOf(84, 0));
    expect(mainnetView.deriveAddress(0).startsWith('bc1')).toBe(true);
    expect(mainnetView.xpub().startsWith('xpub')).toBe(true);
  });
});
