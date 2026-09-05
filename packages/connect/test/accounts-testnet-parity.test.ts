import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { bytesToHex, hexToBytes } from '../src/core/bytes';
import type { BtcPurpose, EraErrorCode, RawAccountEntry } from '../src/index';
import { EraAccounts, EraSdkError, formatPath, parseMultiAccountsUr, Ur } from '../src/index';

/**
 * Parity against `test/fixtures/accounts-testnet.json` — the SHARED artifact
 * for Bitcoin account selection, read verbatim by this SDK and by its Dart
 * sibling. The wallet blob is test INPUT (built once with an SDK's own
 * encoder); every EXPECTATION in it is an independently derived published
 * BIP-32/49/84 vector and is never regenerated from an implementation, so a
 * port that drifts fails here rather than agreeing with itself.
 *
 * What the fixture cannot express stays in `accounts.test.ts`: the refusals
 * it only MARKS (`throws:<code>`), the null answers, and the classification
 * of a coin-type-1' path. Refusals are pinned on both the `code` (the API
 * integrators branch on) and the message, so neither half can drift.
 *
 * The file states the same wallet TWICE — as `wallet.cborHex` and as
 * `wallet.ur` — and every expectation below is derived from the FIRST. The
 * second is therefore pinned only by the cross-check in "the two
 * representations state the same wallet": without it, a UR carrying a flipped
 * public-key byte and a recomputed CRC32 rides along unnoticed.
 */
interface FixtureEntry {
  readonly path: string;
  readonly xfp: string;
  readonly publicKeyHex: string;
  readonly chainCodeHex: string;
  readonly parentFingerprint: string;
}

interface FixtureAccount {
  readonly name: string;
  readonly purpose: number;
  readonly testnet: boolean;
  readonly accountPath: string;
  readonly xfp: string;
  readonly receivePath0: string;
  readonly changePath0: string;
  readonly deriveAddress: 'supported' | 'throws:invalid-props';
  readonly receive: readonly string[];
  readonly change0: string | null;
  readonly xpub: string;
  readonly zpub: string;
}

/**
 * SHA-256 of the shared fixture exactly as it sits on disk. The SIBLING SDK
 * carries a byte-identical copy at its own path and pins this SAME constant,
 * which is the only thing making the two files one artifact rather than two
 * that used to match. This repo's formatter covers JSON, so `biome.jsonc`
 * excludes the path — see the comment on the exclusion — but an editor, a
 * merge or a hand edit still can, and that is what this catches. Changing the
 * fixture on purpose means regenerating it in BOTH repos and updating the
 * constant in BOTH suites.
 */
const SHARED_FIXTURE_SHA256 = 'c754db2221e3758258b0b9b9e9b84a4fc6b3478d2e81fa44760aa251fef7822d';

const fixtureBytes = readFileSync(join(__dirname, 'fixtures', 'accounts-testnet.json'));

const fixture = JSON.parse(fixtureBytes.toString('utf8')) as {
  readonly note: string;
  readonly wallet: {
    readonly cborHex: string;
    readonly ur: string;
    readonly masterFingerprint: string;
    readonly entries: readonly FixtureEntry[];
  };
  readonly accounts: readonly FixtureAccount[];
};

const wallet = fixture.wallet;
const accounts = EraAccounts.fromUr(new Ur('crypto-multi-accounts', hexToBytes(wallet.cborHex)));

/** Pin a refusal on BOTH halves: the stable `code` and the human message. */
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

/**
 * Every field of a raw entry, as comparable values. The views expose only
 * what they need, so a field-by-field comparison of two representations has
 * to go through the raw parse.
 */
function describeEntry(entry: RawAccountEntry): Record<string, unknown> {
  return {
    path: formatPath([...entry.path]),
    xfp: entry.xfp,
    publicKey: entry.publicKey === null ? null : bytesToHex(entry.publicKey),
    chainCode: entry.chainCode === null ? null : bytesToHex(entry.chainCode),
    parentFingerprint: entry.parentFingerprint,
    name: entry.name,
    note: entry.note,
  };
}

const rawFromCbor = parseMultiAccountsUr(
  new Ur('crypto-multi-accounts', hexToBytes(wallet.cborHex)),
);

describe('accounts testnet parity: the shared file', () => {
  it('is byte-for-byte the artifact both SDKs read', () => {
    // Not a checksum of something this suite computed — a checksum of the
    // FILE, so a reformat, a re-ordering or a hand edit on either side fails
    // here instead of silently diverging from the sibling's copy.
    expect(createHash('sha256').update(fixtureBytes).digest('hex')).toBe(SHARED_FIXTURE_SHA256);
  });
});

describe('accounts testnet parity: the export', () => {
  it('states the same wallet in both representations', () => {
    // `cborHex` and `ur` are two spellings of ONE export, and every
    // expectation in the file is derived from the first. Comparing them on a
    // fingerprint and a path list leaves the key material of the second
    // unpinned: a UR whose first public key ends `4b` instead of `b4`,
    // re-CRC'd, passes that comparison and changes every address a reader of
    // `wallet.ur` would derive. So compare the parses field for field.
    const rawFromUrString = parseMultiAccountsUr(wallet.ur);
    expect(rawFromUrString.masterFingerprint).toBe(rawFromCbor.masterFingerprint);
    expect(rawFromUrString.deviceName).toBe(rawFromCbor.deviceName);
    expect(rawFromUrString.deviceId).toBe(rawFromCbor.deviceId);
    expect(rawFromUrString.deviceVersion).toBe(rawFromCbor.deviceVersion);
    expect(rawFromUrString.entries.length).toBe(rawFromCbor.entries.length);
    expect(rawFromUrString.entries.map(describeEntry)).toEqual(
      rawFromCbor.entries.map(describeEntry),
    );
  });

  it('parses the same wallet from the UR string form', () => {
    const fromString = EraAccounts.fromUr(wallet.ur);
    expect(fromString.sourceUr).toBe(wallet.ur);
    expect(fromString.masterFingerprint).toBe(wallet.masterFingerprint);
    expect(fromString.keys.map((k) => k.path)).toEqual(wallet.entries.map((e) => e.path));
  });

  it('carries every entry: path, origin xfp and key material', () => {
    expect(accounts.masterFingerprint).toBe(wallet.masterFingerprint);
    expect(accounts.keys.length).toBe(wallet.entries.length);
    accounts.keys.forEach((key, i) => {
      const want = wallet.entries[i]!;
      expect(key.path).toBe(want.path);
      expect(key.xfp).toBe(want.xfp);
      expect(bytesToHex(key.publicKey!)).toBe(want.publicKeyHex);
      expect(bytesToHex(key.chainCode!)).toBe(want.chainCodeHex);
    });
  });

  it('carries the parent fingerprint each extended key is serialised with', () => {
    const raw = parseMultiAccountsUr(wallet.ur);
    raw.entries.forEach((entry, i) => {
      expect((entry.parentFingerprint ?? 0).toString(16).padStart(8, '0')).toBe(
        wallet.entries[i]!.parentFingerprint,
      );
    });
  });

  it('puts the testnet entries first, and mainnet still skips past them', () => {
    // The fixture is ordered this way on purpose: a selector that returned
    // the first Bitcoin-looking entry would hand a mainnet caller a testnet
    // account, and this is where that fails loudly.
    expect(accounts.keys[0]!.path).toBe("m/84'/1'/0'");
    expect(accounts.btc()!.accountPath).toBe("m/84'/0'/0'");
  });
});

describe('accounts testnet parity: selection', () => {
  for (const want of fixture.accounts) {
    it(want.name, () => {
      const purpose = want.purpose as BtcPurpose;
      const btc = accounts.btc({ purpose, testnet: want.testnet });
      expect(btc, 'no account selected').toBeDefined();
      const view = btc!;

      expect(view.accountPath).toBe(want.accountPath);
      expect(view.purpose).toBe(want.purpose);
      expect(view.xfp).toBe(want.xfp);
      expect(view.receivePath(0)).toBe(want.receivePath0);
      expect(view.changePath(0)).toBe(want.changePath0);
      expect(view.xpub()).toBe(want.xpub);

      want.receive.forEach((address, index) => {
        expect(view.deriveAddress(index), `receive ${index}`).toBe(address);
      });
      if (want.change0 !== null) {
        expect(view.deriveAddress(0, { change: true })).toBe(want.change0);
      }

      if (want.deriveAddress === 'throws:invalid-props') {
        expect(want.receive).toHaveLength(0);
        expect(want.change0).toBeNull();
        expectRefusal(() => view.deriveAddress(0), 'invalid-props', TAPROOT_REFUSAL);
        expectRefusal(
          () => view.deriveAddress(0, { change: true }),
          'invalid-props',
          TAPROOT_REFUSAL,
        );
      } else {
        expect(want.deriveAddress).toBe('supported');
        expect(want.receive.length).toBeGreaterThan(0);
      }

      if (want.zpub === 'throws:invalid-props') {
        expect(want.purpose).not.toBe(84);
        expectRefusal(() => view.zpub(), 'invalid-props', ZPUB_REFUSAL);
      } else {
        expect(want.purpose).toBe(84);
        expect(view.zpub()).toBe(want.zpub);
      }
    });
  }
});
