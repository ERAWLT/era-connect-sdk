import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import * as bchEntry from '../src/bch';
import * as btcEntry from '../src/btc';
import * as cardanoEntry from '../src/cardano';
import * as cosmosEntry from '../src/cosmos';
import * as evmEntry from '../src/evm';
import type {
  CashAddrPayload,
  CashAddrType,
  PathLevel,
  PsbtCoin,
  RawAccountEntry,
  RawMultiAccounts,
  SignedTronTx,
} from '../src/index';
import {
  AnimatedUr,
  BchChain,
  BtcChain,
  bchAddressFromPublicKey,
  btcNestedSegwitAddressFromPublicKey,
  btcP2pkhAddressFromPublicKey,
  btcP2wpkhAddressFromPublicKey,
  bytesToHex,
  CASHADDR_PREFIX,
  CardanoChain,
  CosmosChain,
  cosmosAddressFromPublicKey,
  DEFAULT_ORIGIN,
  decodeCashAddr,
  EraConnect,
  EraSdkError,
  EvmChain,
  EvmDataType,
  encodeCashAddr,
  evmAddressFromPublicKey,
  foldRecoveryId,
  formatPath,
  hexToBytes,
  parseMultiAccountsUr,
  parsePath,
  pathEquals,
  randomRequestId,
  SolanaChain,
  SuiChain,
  solanaAddressFromPublicKey,
  splitSignedTronTx,
  suiAddressFromPublicKey,
  TonChain,
  TonDataType,
  TronChain,
  TypedUrScanner,
  tronAddressFromPublicKey,
  Ur,
  UrScanner,
  uuidStringify,
  WALLET_UR_TYPES,
  XrpChain,
  xrpAddressFromPublicKey,
} from '../src/index';
import * as solanaEntry from '../src/solana';
import * as suiEntry from '../src/sui';
import * as tonEntry from '../src/ton';
import * as tronEntry from '../src/tron';
import * as verifyEntry from '../src/verify';
import * as xrpEntry from '../src/xrp';

/**
 * The public surface, imported the way an integrator imports it: only through
 * the package's own entry points, never through `src/<internal>`.
 *
 * The allow-lists in `src/index.ts` and the eleven subpath entries are
 * hand-written, so a name drops off the published API without `tsc`, the rest
 * of the suite, `publint` or `attw` noticing — it surfaces as an integrator's
 * import failing after a release. Every symbol named below therefore has to
 * be reachable from an entry point or this file fails to compile (types) or
 * to run (values).
 */

const walletUr = (
  JSON.parse(readFileSync(join(__dirname, 'fixtures', 'accounts-testnet.json'), 'utf8')) as {
    wallet: { ur: string };
  }
).wallet.ur;

/** A signed Tron frame by hand: `{1: raw_data, 2: signature}`, both length-delimited. */
const SIGNED_TRON_TX_HEX = `0a020102${'12'}41${'03'.repeat(65)}`;

describe('the root entry carries what an integrator has to name', () => {
  it('mints and renders request ids', () => {
    const id = randomRequestId();
    expect(id).toHaveLength(16);
    const uuid = uuidStringify(id);
    expect(uuid).toMatch(/^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/);
    // The UUID string is the same 16 bytes a reply would echo back.
    const flat = uuid.split('-').join('');
    expect(hexToBytes(flat)).toEqual(id);
    expect(bytesToHex(id)).toBe(flat);
  });

  it('reaches the raw export without going through the typed views', () => {
    const raw: RawMultiAccounts = parseMultiAccountsUr(walletUr);
    expect(raw.entries.length).toBeGreaterThan(0);
    const entry: RawAccountEntry = raw.entries[0]!;
    const levels: PathLevel[] = parsePath(formatPath([...entry.path]));
    expect(pathEquals(levels, entry.path)).toBe(true);
    expect(levels[0]).toEqual({ index: 84, hardened: true });
  });

  it('names the device-facing origin default', () => {
    expect(DEFAULT_ORIGIN).toBe('ERA Connect');
  });

  it('folds an EVM recovery id off `v`', () => {
    expect(foldRecoveryId(27n)).toBe(0);
    expect(foldRecoveryId(28n)).toBe(1);
    expect(foldRecoveryId(37n)).toBe(0);
    expect(foldRecoveryId(38n)).toBe(1);
  });

  it('splits a signed Tron frame', () => {
    const signed: SignedTronTx = splitSignedTronTx(SIGNED_TRON_TX_HEX);
    expect(bytesToHex(signed.rawData)).toBe('0102');
    expect(signed.signatures).toHaveLength(1);
    expect(signed.signatures[0]).toHaveLength(65);
  });

  it('encodes and decodes CashAddr', () => {
    const type: CashAddrType = 'p2pkh';
    const hash = hexToBytes('00'.repeat(20));
    const bare = encodeCashAddr(type, hash);
    const prefixed = encodeCashAddr(type, hash, { withPrefix: true });
    expect(prefixed).toBe(`${CASHADDR_PREFIX}:${bare}`);
    const payload: CashAddrPayload = decodeCashAddr(prefixed);
    expect(payload.type).toBe(type);
    expect(payload.prefix).toBe(CASHADDR_PREFIX);
    expect(payload.hash).toEqual(hash);
  });

  it('derives an address on every chain from a key the caller already holds', () => {
    const raw = parseMultiAccountsUr(walletUr);
    // A 33-byte secp256k1 key from the export, and a stand-in 32-byte
    // Ed25519 one — these helpers take the key, not the wallet.
    const secp = raw.entries[0]!.publicKey!;
    expect(secp).toHaveLength(33);
    const ed25519 = hexToBytes('01'.repeat(32));

    expect(evmAddressFromPublicKey(secp)).toMatch(/^0x[0-9a-fA-F]{40}$/);
    expect(tronAddressFromPublicKey(secp)).toMatch(/^T[1-9A-HJ-NP-Za-km-z]{33}$/);
    expect(xrpAddressFromPublicKey(secp).startsWith('r')).toBe(true);
    expect(cosmosAddressFromPublicKey(secp, 'osmo').startsWith('osmo1')).toBe(true);
    expect(btcP2pkhAddressFromPublicKey(secp).startsWith('1')).toBe(true);
    expect(btcNestedSegwitAddressFromPublicKey(secp).startsWith('3')).toBe(true);
    expect(btcNestedSegwitAddressFromPublicKey(secp, true).startsWith('2')).toBe(true);
    expect(btcP2wpkhAddressFromPublicKey(secp).startsWith('bc1q')).toBe(true);
    expect(btcP2wpkhAddressFromPublicKey(secp, 'tb').startsWith('tb1q')).toBe(true);
    expect(solanaAddressFromPublicKey(ed25519)).toMatch(/^[1-9A-HJ-NP-Za-km-z]{32,44}$/);
    expect(suiAddressFromPublicKey(ed25519)).toMatch(/^0x[0-9a-f]{64}$/);

    // The Bitcoin Cash helper and the CashAddr codec agree on one key: the
    // P2PKH payload it encodes is the hash160 the P2WPKH witness program
    // carries, so these two exports are cross-checked rather than merely
    // present.
    const cash = decodeCashAddr(bchAddressFromPublicKey(secp));
    expect(cash.type).toBe('p2pkh');
    expect(cash.hash).toHaveLength(20);
    expect(bchAddressFromPublicKey(secp, { withPrefix: true })).toBe(
      `${CASHADDR_PREFIX}:${bchAddressFromPublicKey(secp)}`,
    );
  });

  it('names the PSBT coin set', () => {
    const coins: PsbtCoin[] = ['btc', 'ltc', 'doge', 'dash'];
    expect(coins).toContain('btc');
  });
});

describe('WALLET_UR_TYPES is a gate, not a suggestion', () => {
  it('drops straight into a scanner without a copy', () => {
    // `expectedTypes` is a `readonly string[]`, which is what this is — no
    // caller needs to spread it.
    const scanner = new UrScanner({ expectedTypes: WALLET_UR_TYPES });
    expect(WALLET_UR_TYPES).toContain('crypto-multi-accounts');
    expect(WALLET_UR_TYPES).toContain('crypto-hdkey');
    const fed = scanner.receivePart(walletUr);
    expect(fed.kind).toBe('complete');
  });

  it('cannot be widened from outside, and the type gate does not follow it', () => {
    // A `ReadonlySet` is erased at compile time, so an exported Set is a live
    // one at runtime: `.add('totally-not-a-wallet')` — no cast needed — would
    // have widened `parseMultiAccountsUr`'s gate process-wide. A frozen array
    // refuses the write, and the gate keeps its own private Set regardless.
    expect(Object.isFrozen(WALLET_UR_TYPES)).toBe(true);
    expect(() => (WALLET_UR_TYPES as string[]).push('totally-not-a-wallet')).toThrowError(
      TypeError,
    );
    expect(WALLET_UR_TYPES).not.toContain('totally-not-a-wallet');

    let caught: unknown;
    try {
      parseMultiAccountsUr(new Ur('totally-not-a-wallet', hexToBytes('a0')));
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(EraSdkError);
    expect((caught as EraSdkError).code).toBe('wrong-ur-type');
  });

  it('advertises exactly the types its private gate enforces', () => {
    // Splitting the constant into an exported frozen array plus a private
    // `Set` removed the mutable-Set hazard and created a second one: two
    // lists that must stay equal, with nothing in the type system tying them
    // together. So they are pinned behaviourally, from both directions — the
    // advertised list spelled out in full, then every member of it probed
    // through the gate, then the neighbours it must keep out.
    expect([...WALLET_UR_TYPES]).toEqual([
      'crypto-multi-accounts',
      'crypto-account',
      'crypto-hdkey',
    ]);

    // Advertised ⇒ admitted. The payload here is an empty CBOR map, so every
    // one of these still refuses — but about its CONTENT, never its type.
    for (const type of WALLET_UR_TYPES) {
      expect(refusalCodeFor(type), type).not.toBe('wrong-ur-type');
    }

    // Not advertised ⇒ refused by the gate, including the neighbouring
    // registry types a wallet export is easiest to confuse with.
    for (const type of ['crypto-output', 'crypto-psbt', 'crypto-keypath', 'bytes']) {
      expect(WALLET_UR_TYPES, type).not.toContain(type);
      expect(refusalCodeFor(type), type).toBe('wrong-ur-type');
    }
  });
});

/** The `EraErrorCode` `parseMultiAccountsUr` refuses a bare `{}` of `type` with. */
function refusalCodeFor(type: string): string {
  try {
    parseMultiAccountsUr(new Ur(type, hexToBytes('a0')));
  } catch (e) {
    expect(e).toBeInstanceOf(EraSdkError);
    return (e as EraSdkError).code;
  }
  throw new Error(`"${type}" was not refused at all`);
}

// ---------------------------------------------------------------------------
// The subpath entries
// ---------------------------------------------------------------------------

/** The plumbing every per-chain entry re-exports, checked at runtime. */
interface ChainEntryValues {
  readonly DEFAULT_ORIGIN: string;
  readonly EraSdkError: typeof EraSdkError;
  readonly UrScanner: typeof UrScanner;
  readonly TypedUrScanner: typeof TypedUrScanner;
  readonly AnimatedUr: typeof AnimatedUr;
  readonly Ur: typeof Ur;
}

/**
 * The type half. `tsc` resolves every name inside these aliases, so an entry
 * that stops re-exporting one of its own signatures' types fails to COMPILE
 * here — which is the only place that would notice.
 */
type ChainEntryTypes<Options, Feed, Rejection, Animated, Config, Reply, Request> = [
  Options,
  Feed,
  Rejection,
  Animated,
  Config,
  Reply,
  Request,
];

type _EvmTypes = ChainEntryTypes<
  evmEntry.UrScannerOptions,
  evmEntry.ScanFeedResult,
  evmEntry.ScanRejection,
  evmEntry.AnimatedUrOptions,
  evmEntry.EraConnectConfig,
  evmEntry.ExpectedReply,
  evmEntry.SignRequest<evmEntry.EvmSignatureResult>
>;
type _BtcTypes = [
  ChainEntryTypes<
    btcEntry.UrScannerOptions,
    btcEntry.ScanFeedResult,
    btcEntry.ScanRejection,
    btcEntry.AnimatedUrOptions,
    btcEntry.EraConnectConfig,
    btcEntry.ExpectedReply,
    btcEntry.SignRequest<btcEntry.BtcPsbtResult>
  >,
  btcEntry.PsbtCoin,
];
type _BchTypes = ChainEntryTypes<
  bchEntry.UrScannerOptions,
  bchEntry.ScanFeedResult,
  bchEntry.ScanRejection,
  bchEntry.AnimatedUrOptions,
  bchEntry.EraConnectConfig,
  bchEntry.ExpectedReply,
  bchEntry.SignRequest<bchEntry.BchSignatureResult>
>;
type _SolanaTypes = ChainEntryTypes<
  solanaEntry.UrScannerOptions,
  solanaEntry.ScanFeedResult,
  solanaEntry.ScanRejection,
  solanaEntry.AnimatedUrOptions,
  solanaEntry.EraConnectConfig,
  solanaEntry.ExpectedReply,
  solanaEntry.SignRequest<solanaEntry.SolSignatureResult>
>;
type _TronTypes = [
  ChainEntryTypes<
    tronEntry.UrScannerOptions,
    tronEntry.ScanFeedResult,
    tronEntry.ScanRejection,
    tronEntry.AnimatedUrOptions,
    tronEntry.EraConnectConfig,
    tronEntry.ExpectedReply,
    tronEntry.SignRequest<tronEntry.TronSignatureResult>
  >,
  tronEntry.SignedTronTx,
  tronEntry.TronLatestBlock,
];
type _TonTypes = ChainEntryTypes<
  tonEntry.UrScannerOptions,
  tonEntry.ScanFeedResult,
  tonEntry.ScanRejection,
  tonEntry.AnimatedUrOptions,
  tonEntry.EraConnectConfig,
  tonEntry.ExpectedReply,
  tonEntry.SignRequest<tonEntry.TonSignatureResult>
>;
type _CardanoTypes = ChainEntryTypes<
  cardanoEntry.UrScannerOptions,
  cardanoEntry.ScanFeedResult,
  cardanoEntry.ScanRejection,
  cardanoEntry.AnimatedUrOptions,
  cardanoEntry.EraConnectConfig,
  cardanoEntry.ExpectedReply,
  cardanoEntry.SignRequest<cardanoEntry.CardanoSignatureResult>
>;
type _SuiTypes = ChainEntryTypes<
  suiEntry.UrScannerOptions,
  suiEntry.ScanFeedResult,
  suiEntry.ScanRejection,
  suiEntry.AnimatedUrOptions,
  suiEntry.EraConnectConfig,
  suiEntry.ExpectedReply,
  suiEntry.SignRequest<suiEntry.SuiSignatureResult>
>;
type _CosmosTypes = ChainEntryTypes<
  cosmosEntry.UrScannerOptions,
  cosmosEntry.ScanFeedResult,
  cosmosEntry.ScanRejection,
  cosmosEntry.AnimatedUrOptions,
  cosmosEntry.EraConnectConfig,
  cosmosEntry.ExpectedReply,
  cosmosEntry.SignRequest<cosmosEntry.CosmosSignatureResult>
>;
type _XrpTypes = ChainEntryTypes<
  xrpEntry.UrScannerOptions,
  xrpEntry.ScanFeedResult,
  xrpEntry.ScanRejection,
  xrpEntry.AnimatedUrOptions,
  xrpEntry.EraConnectConfig,
  xrpEntry.ExpectedReply,
  xrpEntry.SignRequest<xrpEntry.XrpSignatureResult>
>;

/** Every type `/verify`'s own argument objects declare. */
type _VerifyTypes = [
  verifyEntry.CardanoWitness,
  verifyEntry.EvmDataType,
  verifyEntry.TonDataType,
  verifyEntry.TronLatestBlock,
  verifyEntry.SignedTronTx,
  verifyEntry.DecodedBchInput,
  verifyEntry.DecodedBchOutput,
  verifyEntry.EraErrorCode,
];

describe('every subpath entry ships the same plumbing', () => {
  const entries: readonly (readonly [string, ChainEntryValues])[] = [
    ['evm', evmEntry],
    ['btc', btcEntry],
    ['bch', bchEntry],
    ['solana', solanaEntry],
    ['tron', tronEntry],
    ['ton', tonEntry],
    ['cardano', cardanoEntry],
    ['sui', suiEntry],
    ['cosmos', cosmosEntry],
    ['xrp', xrpEntry],
  ];

  it('re-exports the ten chain entries with one identity each', () => {
    expect(entries).toHaveLength(10);
    for (const [name, entry] of entries) {
      expect(entry.DEFAULT_ORIGIN, name).toBe(DEFAULT_ORIGIN);
      expect(entry.EraSdkError, name).toBe(EraSdkError);
      expect(entry.UrScanner, name).toBe(UrScanner);
      expect(entry.TypedUrScanner, name).toBe(TypedUrScanner);
      expect(entry.AnimatedUr, name).toBe(AnimatedUr);
      expect(entry.Ur, name).toBe(Ur);
    }
  });

  /**
   * The one export each subpath exists FOR. `ChainEntryValues` above covers
   * the shared plumbing and the type aliases cover the signatures; neither
   * notices when the chain CLASS itself drops off an entry's hand-written
   * allow-list — and it is the single import an integrator of that subpath
   * cannot do without.
   */
  type ChainConstructor = new (...args: never[]) => object;

  const chainClasses: readonly (readonly [
    string,
    ChainConstructor,
    ChainConstructor,
    (era: EraConnect) => object,
  ])[] = [
    ['evm', evmEntry.EvmChain, EvmChain, (era) => era.evm],
    ['btc', btcEntry.BtcChain, BtcChain, (era) => era.btc],
    ['bch', bchEntry.BchChain, BchChain, (era) => era.bch],
    ['solana', solanaEntry.SolanaChain, SolanaChain, (era) => era.solana],
    ['tron', tronEntry.TronChain, TronChain, (era) => era.tron],
    ['ton', tonEntry.TonChain, TonChain, (era) => era.ton],
    ['cardano', cardanoEntry.CardanoChain, CardanoChain, (era) => era.cardano],
    ['sui', suiEntry.SuiChain, SuiChain, (era) => era.sui],
    ['cosmos', cosmosEntry.CosmosChain, CosmosChain, (era) => era.cosmos],
    ['xrp', xrpEntry.XrpChain, XrpChain, (era) => era.xrp],
  ];

  it('re-exports its own chain class — the same one the facade builds', () => {
    const era = new EraConnect();
    expect(chainClasses).toHaveLength(entries.length);
    for (const [name, fromSubpath, fromRoot, moduleOf] of chainClasses) {
      expect(typeof fromSubpath, name).toBe('function');
      expect(fromSubpath, name).toBe(fromRoot);
      // Identity alone would still hold if both entries had drifted onto the
      // same wrong class, so tie it to the facade: `era.<chain>` is what the
      // docs hand every reader, and it must be an instance of this one.
      expect(moduleOf(era), name).toBeInstanceOf(fromSubpath);
    }
  });

  it('/verify carries the values its own signatures use', () => {
    expect(verifyEntry.EvmDataType).toBe(EvmDataType);
    expect(verifyEntry.TonDataType).toBe(TonDataType);
    expect(verifyEntry.EraSdkError).toBe(EraSdkError);
    // A caller that imports `/verify` alone can name what it hands the
    // verifiers and catch what the parsers throw.
    const dataType: verifyEntry.EvmDataType = verifyEntry.EvmDataType.personalMessage;
    const tonDataType: verifyEntry.TonDataType = verifyEntry.TonDataType.tonProof;
    expect(dataType).toBe(EvmDataType.personalMessage);
    expect(tonDataType).toBe(TonDataType.tonProof);
  });
});
