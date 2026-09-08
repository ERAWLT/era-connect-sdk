import { EraSdkError } from '../core/errors';
import type { PathLevel } from '../registry/keypath';
import { formatPath, parsePath, pathEquals, xfpToHex } from '../registry/keypath';
import type { RawAccountEntry, RawMultiAccounts } from '../registry/multi-accounts';
import { parseMultiAccountsUr } from '../registry/multi-accounts';
import type { Ur } from '../ur/ur';
import type { Bech32Hrp } from './derive';
import {
  bchAddressFromPublicKey,
  btcNestedSegwitAddressFromPublicKey,
  btcP2pkhAddressFromPublicKey,
  btcP2wpkhAddressFromPublicKey,
  btcTaprootAddressFromPublicKey,
  cardanoBaseAddress,
  cardanoSoftDerivePath,
  cosmosAddressFromPublicKey,
  derivePublicKey,
  derivePublicKeyChild,
  ethermintAddressFromPublicKey,
  nestedSegwitAddressFromPublicKey,
  p2pkhAddressFromPublicKey,
  evmAddressFromPublicKey,
  serializeExtendedPublicKey,
  solanaAddressFromPublicKey,
  suiAddressFromPublicKey,
  tonAddressFromPublicKey,
  TPUB_VERSION,
  tronAddressFromPublicKey,
  VPUB_VERSION,
  XPUB_VERSION,
  xrpAddressFromPublicKey,
  ZPUB_VERSION,
} from './derive';

/** Chain family of an exported account, matched by its derivation path — never by the note label. */
export type AccountChain =
  | 'evm'
  /**
   * Bitcoin MAINNET, at coin type 0' — all four purposes (44/49/84/86).
   *
   * A coin-type-1' path is deliberately NOT reported as Bitcoin. SLIP-44
   * assigns coin type 1 to "Testnet (all coins)", so `m/84'/1'/0'` is as much
   * a Litecoin testnet account as a Bitcoin one — and this SDK's own
   * `PsbtCoin` admits ltc, doge and dash. Attribution has no caller intent to
   * lean on, so it must stay `unknown` rather than guess. `btc({ testnet:
   * true })` resolves that very path only because the caller named the chain.
   * Do not "fix" `classify` to widen this.
   */
  | 'btc'
  | 'bch'
  /**
   * The Bitcoin-like altcoins the device exports, at their own MAINNET coin
   * types — Litecoin 2', Dogecoin 3', Dash 5'. Unlike coin type 1' these are
   * unambiguous, so attribution needs no caller intent.
   */
  | 'litecoin'
  | 'dogecoin'
  | 'dash'
  | 'solana'
  | 'tron'
  | 'ton'
  | 'cardano'
  | 'sui'
  | 'cosmos'
  | 'xrp'
  | 'unknown';

export interface AccountKey {
  readonly chain: AccountChain;
  /** Account-level derivation path, e.g. `m/44'/60'/0'`. */
  readonly path: string;
  /**
   * The source fingerprint a `*-sign-request` keypath must carry for this
   * account (lowercase 8-hex). NOT necessarily the master fingerprint.
   */
  readonly xfp: string;
  /** 33-byte compressed secp256k1, or 32-byte Ed25519 (Solana); absent when the export omitted it. */
  readonly publicKey: Uint8Array | undefined;
  readonly chainCode: Uint8Array | undefined;
  readonly name: string | undefined;
  /** Derivation-scheme label (`account.standard`, ...) — display only. */
  readonly note: string | undefined;
}

export interface DeviceInfo {
  readonly name: string | undefined;
  readonly id: string | undefined;
  readonly firmwareVersion: string | undefined;
}

function classify(path: readonly PathLevel[]): AccountChain {
  const p0 = path[0];
  const p1 = path[1];
  if (!p0 || !p1 || !p0.hardened || !p1.hardened) return 'unknown';
  if (p0.index === 44 && p1.index === 60) return 'evm';
  // Coin type 0' only, on purpose — see the `btc` member of AccountChain.
  if (
    p1.index === 0 &&
    (p0.index === 84 || p0.index === 49 || p0.index === 44 || p0.index === 86)
  ) {
    return 'btc';
  }
  if (p0.index === 44 && p1.index === 145) return 'bch';
  if (p1.index === 2 && (p0.index === 84 || p0.index === 49 || p0.index === 44)) {
    return 'litecoin';
  }
  if (p0.index === 44 && p1.index === 3) return 'dogecoin';
  if (p0.index === 44 && p1.index === 5) return 'dash';
  if (p0.index === 44 && p1.index === 501) return 'solana';
  if (p0.index === 44 && p1.index === 195) return 'tron';
  if (p0.index === 44 && p1.index === 607) return 'ton';
  if (p0.index === 1852 && p1.index === 1815) return 'cardano';
  if (p0.index === 44 && p1.index === 784) return 'sui';
  // The non-118 Cosmos zones, each on its own SLIP-44 coin type. The
  // Ethermint zones are deliberately absent: they sit on m/44'/60' and stay
  // classified as `evm`, because that is what their key is — `cosmos('inj')`
  // reaches them through the EVM account.
  if (p0.index === 44 && COSMOS_SLIP44.has(p1.index)) return 'cosmos';
  if (p0.index === 44 && p1.index === 144) return 'xrp';
  return 'unknown';
}

/**
 * An EVM ACCOUNT, as opposed to anything else that starts `m/44'/60'`.
 *
 * `classify` reads only the first two path levels, and three different things
 * share those: the standard account `m/44'/60'/<account>'` (depth 3, with a
 * chain code), the Ledger Live entries `m/44'/60'/<n>'/0/0` (depth 5, fully
 * derived leaves) and the Ethermint keys that Injective, Evmos and Dymension
 * are exported under, which sit at `m/44'/60'/0'/0/0` and carry no chain code
 * at all.
 *
 * Without this, `evm()` could hand back one of those leaves — and a view over
 * a leaf reports a leaf path as its account path and derives two levels BELOW
 * it, producing a real key at a nonsense path. A wrong address that looks
 * entirely plausible is the worst failure this SDK can have, so the account
 * shape is checked rather than assumed.
 *
 * Depth is the whole test. Key material deliberately is NOT: an entry with no
 * public key and no chain code still resolves its xfp for signing, which is
 * reference behaviour the views depend on, and `withChainCode` already refuses
 * derivation on such an entry with a typed error.
 */
function isEvmAccount(entry: RawAccountEntry): boolean {
  return classify(entry.path) === 'evm' && entry.path.length === 3;
}

function withChainCode(entry: RawAccountEntry): Uint8Array {
  if (!entry.chainCode) {
    throw new EraSdkError(
      'account-not-found',
      `account ${formatPath([...entry.path])} carries no chain code; cannot derive children`,
    );
  }
  return entry.chainCode;
}

/** The entry's key at the required length, or a typed refusal (derivation only). */
function requireKey(entry: RawAccountEntry, length: number): Uint8Array {
  if (!entry.publicKey || entry.publicKey.length !== length) {
    throw new EraSdkError(
      'invalid-props',
      `account ${formatPath([...entry.path])} carries no ${length}-byte public key; ` +
        'xfp lookup still works, address derivation does not',
    );
  }
  return entry.publicKey;
}

/** EVM view over the linked wallet: one account xpub, addresses derived at `0/index`. */
export class EvmAccountView {
  constructor(
    private readonly entry: RawAccountEntry,
    private readonly resolvedXfp: number,
  ) {}

  get xfp(): string {
    return xfpToHex(this.resolvedXfp);
  }

  get accountPath(): string {
    return formatPath([...this.entry.path]);
  }

  /** Signing path for address `index`: `<account>/0/<index>`. */
  pathFor(index: number): string {
    return `${this.accountPath}/0/${index}`;
  }

  deriveAddress(index: number): `0x${string}` {
    return evmAddressFromPublicKey(
      derivePublicKey(requireKey(this.entry, 33), withChainCode(this.entry), 0, index),
    );
  }

  xpub(): string {
    return extendedKeyOf(this.entry);
  }
}

/**
 * An EVM account under one of Ledger's two alternative schemes.
 *
 * The device exports three EVM derivations, and `evm()` answers only the
 * standard one. These two were invisible: `ledger-live` ships ten fully
 * derived leaves at `m/44'/60'/<n>'/0/0` — one key per account, nothing to
 * derive further — while `ledger-legacy` is an account whose addresses sit ONE
 * level below it, at `m/44'/60'/0'/<index>`, not two.
 */
export type EvmLedgerScheme = 'ledger-live' | 'ledger-legacy';

export class EvmLedgerAccountView {
  constructor(
    private readonly entry: RawAccountEntry,
    private readonly resolvedXfp: number,
    readonly scheme: EvmLedgerScheme,
  ) {}

  get xfp(): string {
    return xfpToHex(this.resolvedXfp);
  }

  /** The exported path: an account for `ledger-legacy`, a leaf for `ledger-live`. */
  get path(): string {
    return formatPath([...this.entry.path]);
  }

  /**
   * `ledger-live`: the address of the exported key itself, which is all the
   * export carries. `ledger-legacy`: the address at `<account>/<index>`.
   */
  deriveAddress(index = 0): `0x${string}` {
    if (this.scheme === 'ledger-live') {
      if (index !== 0) {
        throw new EraSdkError(
          'invalid-props',
          'a Ledger Live entry is one already-derived key; ask for another entry, not another index',
        );
      }
      return evmAddressFromPublicKey(requireKey(this.entry, 33));
    }
    return evmAddressFromPublicKey(
      derivePublicKeyChild(requireKey(this.entry, 33), withChainCode(this.entry), index),
    );
  }
}

export type BtcPurpose = 44 | 49 | 84 | 86;

/**
 * The only purposes `btc()` resolves an account for. A purpose outside this
 * set has no script type, no address encoding and no SLIP-132 form, so there
 * is nothing a view over it could honestly answer — and TypeScript alone does
 * not bound it: a JavaScript caller, or a cast, reaches the same method.
 */
const BTC_PURPOSES: ReadonlySet<number> = new Set<number>([44, 49, 84, 86]);

/**
 * Whether `entry` is a TESTNET account, read off its coin type. SLIP-44 gives
 * coin type 1 to "Testnet (all coins)"; every other coin type a Bitcoin view
 * can wrap is a mainnet account.
 */
function isTestnetAccount(entry: RawAccountEntry): boolean {
  const coinType = entry.path[1];
  return coinType?.hardened === true && coinType.index === 1;
}

/**
 * Bitcoin view over one exported account. The default is the BIP-84
 * native-segwit account; pass `purpose` to reach the other script types the
 * device exports (44 = legacy P2PKH, 49 = nested segwit, 84 = native segwit,
 * 86 = taproot). Message signing covers 44/49/84 on firmware 2.1.0+ and
 * legacy P2PKH alone on older firmware; Taproot is never message-signable
 * (BIP-137 has no header range for it).
 *
 * The network is a property of the ACCOUNT this view was selected for, not a
 * rendering option: a testnet view exists only when the export carries a
 * coin-type-1' account, and then its addresses, its `accountPath` and its
 * extended keys are all testnet.
 */
export class BtcAccountView {
  private readonly testnet: boolean;

  /**
   * Wraps one selected account. The NETWORK is not a parameter: it is read
   * off `entry`'s own coin type, so a mainnet entry can never be dressed as a
   * testnet account — which is precisely the confident wrong answer this view
   * used to be able to produce.
   */
  constructor(
    private readonly entry: RawAccountEntry,
    readonly purpose: BtcPurpose,
    private readonly resolvedXfp: number,
  ) {
    this.testnet = isTestnetAccount(entry);
  }

  get xfp(): string {
    return xfpToHex(this.resolvedXfp);
  }

  get accountPath(): string {
    return formatPath([...this.entry.path]);
  }

  receivePath(index: number): string {
    return `${this.accountPath}/0/${index}`;
  }

  changePath(index: number): string {
    return `${this.accountPath}/1/${index}`;
  }

  deriveAddress(index: number, options?: { change?: boolean }): string {
    const change = options?.change ? 1 : 0;
    const child = derivePublicKey(
      requireKey(this.entry, 33),
      withChainCode(this.entry),
      change,
      index,
    );
    switch (this.purpose) {
      case 84:
        return btcP2wpkhAddressFromPublicKey(child, this.testnet ? 'tb' : 'bc');
      case 44:
        return btcP2pkhAddressFromPublicKey(child, this.testnet);
      case 49:
        return btcNestedSegwitAddressFromPublicKey(child, this.testnet);
      case 86:
        return btcTaprootAddressFromPublicKey(child, this.testnet ? 'tb' : 'bc');
      // Unreachable through `btc()`, which bounds the purpose — but the
      // constructor is public and `BtcPurpose` is erased at runtime, so a
      // JavaScript caller (or a cast) lands here. Without this arm the switch
      // is exhaustive over the union, `tsc` stays silent and the method
      // returns `undefined` from a signature declared `: string` — which
      // reaches a QR encoder or a change output as the text "undefined".
      default:
        throw new EraSdkError('invalid-props', `unsupported BIP purpose ${this.purpose}`);
    }
  }

  /** Account xpub — a `tpub...` when the account is a testnet one. */
  xpub(): string {
    return extendedKeyOf(this.entry, this.testnet ? TPUB_VERSION : XPUB_VERSION);
  }

  /**
   * SLIP-132 zpub form of the BIP-84 key, for tools that require it. On a
   * testnet account this is the SLIP-132 BIP-84 TESTNET key, which prints as
   * `vpub...`; the method keeps its name and still refuses any purpose other
   * than 84.
   */
  zpub(): string {
    if (this.purpose !== 84) {
      throw new EraSdkError(
        'invalid-props',
        'zpub is the SLIP-132 form of the BIP-84 account only',
      );
    }
    return extendedKeyOf(this.entry, this.testnet ? VPUB_VERSION : ZPUB_VERSION);
  }
}

/** Tron view: addresses derived at `0/index`. */
export class TronAccountView {
  constructor(
    private readonly entry: RawAccountEntry,
    private readonly resolvedXfp: number,
  ) {}

  get xfp(): string {
    return xfpToHex(this.resolvedXfp);
  }

  get accountPath(): string {
    return formatPath([...this.entry.path]);
  }

  pathFor(index: number): string {
    return `${this.accountPath}/0/${index}`;
  }

  deriveAddress(index: number): string {
    return tronAddressFromPublicKey(
      derivePublicKey(requireKey(this.entry, 33), withChainCode(this.entry), 0, index),
    );
  }
}

/** Bitcoin Cash view: `m/44'/145'/0'`, CashAddr P2PKH addresses. */
/** The Bitcoin-like altcoins, which differ only in constants. */
export type UtxoChain = 'litecoin' | 'dogecoin' | 'dash';

interface UtxoChainParams {
  readonly coinType: number;
  /** base58check version byte for P2PKH — Litecoin 48 ("L"), Doge 30 ("D"), Dash 76 ("X"). */
  readonly p2pkh: number;
  /** base58check version byte for P2SH — Litecoin 50 ("M"), Doge 22, Dash 16. */
  readonly p2sh: number;
  /** Segwit HRP, where the chain has segwit at all. */
  readonly hrp?: Bech32Hrp;
  /** BIP purposes the chain's derivation vector actually declares, best first. */
  readonly purposes: readonly number[];
}

/**
 * Taken from each coin's `CoinInfo` in the firmware, not from a registry:
 * these version bytes are the only thing separating one chain's addresses
 * from another's, so they are pinned to the device that produces the keys.
 */
const UTXO_CHAINS: Record<UtxoChain, UtxoChainParams> = {
  litecoin: { coinType: 2, p2pkh: 48, p2sh: 50, hrp: 'ltc', purposes: [84, 49, 44] },
  dogecoin: { coinType: 3, p2pkh: 30, p2sh: 22, purposes: [44] },
  dash: { coinType: 5, p2pkh: 76, p2sh: 16, purposes: [44] },
};

/**
 * A Litecoin, Dogecoin or Dash account.
 *
 * The SDK signed PSBTs for these three long before it could name an address
 * for them: `classify` returned `unknown` and there was no view, so a caller
 * holding a perfectly good Litecoin account had no way to ask this SDK where
 * to receive. The encoding is the same machinery Bitcoin already uses, under
 * different version bytes.
 */
export class UtxoAccountView {
  constructor(
    private readonly entry: RawAccountEntry,
    private readonly resolvedXfp: number,
    readonly chain: UtxoChain,
  ) {}

  private get params(): UtxoChainParams {
    return UTXO_CHAINS[this.chain];
  }

  /** The BIP purpose this account was exported under — 84, 49 or 44. */
  get purpose(): number {
    return this.entry.path[0]!.index;
  }

  get xfp(): string {
    return xfpToHex(this.resolvedXfp);
  }

  get accountPath(): string {
    return formatPath([...this.entry.path]);
  }

  receivePath(index: number): string {
    return `${this.accountPath}/0/${index}`;
  }

  changePath(index: number): string {
    return `${this.accountPath}/1/${index}`;
  }

  derivePublicKey(index: number, options?: { change?: boolean }): Uint8Array {
    return derivePublicKey(
      requireKey(this.entry, 33),
      withChainCode(this.entry),
      options?.change ? 1 : 0,
      index,
    );
  }

  /** The address at receive (or `change:`) `index`, in this account's script type. */
  deriveAddress(index: number, options?: { change?: boolean }): string {
    const child = this.derivePublicKey(index, options);
    const { p2pkh, p2sh, hrp } = this.params;
    switch (this.purpose) {
      case 84:
        if (!hrp) break;
        return btcP2wpkhAddressFromPublicKey(child, hrp);
      case 49:
        return nestedSegwitAddressFromPublicKey(child, p2sh);
      case 44:
        return p2pkhAddressFromPublicKey(child, p2pkh);
    }
    throw new EraSdkError(
      'invalid-props',
      `${this.chain} has no address encoding for BIP purpose ${this.purpose}`,
    );
  }

  xpub(): string {
    return extendedKeyOf(this.entry);
  }
}

export class BchAccountView {
  constructor(
    private readonly entry: RawAccountEntry,
    private readonly resolvedXfp: number,
  ) {}

  get xfp(): string {
    return xfpToHex(this.resolvedXfp);
  }

  get accountPath(): string {
    return formatPath([...this.entry.path]);
  }

  receivePath(index: number): string {
    return `${this.accountPath}/0/${index}`;
  }

  changePath(index: number): string {
    return `${this.accountPath}/1/${index}`;
  }

  /** The compressed public key at receive/change `index` — what a sign request's input names. */
  derivePublicKey(index: number, options?: { change?: boolean }): Uint8Array {
    return derivePublicKey(
      requireKey(this.entry, 33),
      withChainCode(this.entry),
      options?.change ? 1 : 0,
      index,
    );
  }

  /** Bare CashAddr by default; `{ withPrefix: true }` for `bitcoincash:...`. */
  deriveAddress(index: number, options?: { change?: boolean; withPrefix?: boolean }): string {
    return bchAddressFromPublicKey(this.derivePublicKey(index, options), {
      withPrefix: options?.withPrefix ?? false,
    });
  }
}

/**
 * TON view: one Ed25519 key per account (`m/44'/607'/0'`), shared by the
 * V4R2 and V5R1 wallet contracts — the contract version affects only the
 * ADDRESS, which this SDK leaves to TON tooling (derive it from `publicKey`
 * with @ton/core or equivalent).
 */
export class TonAccountView {
  constructor(
    private readonly entry: RawAccountEntry,
    private readonly resolvedXfp: number,
  ) {}

  get xfp(): string {
    return xfpToHex(this.resolvedXfp);
  }

  get accountPath(): string {
    return formatPath([...this.entry.path]);
  }

  /** 32-byte Ed25519 public key — the signer for both wallet-contract versions. */
  get publicKey(): Uint8Array {
    return requireKey(this.entry, 32);
  }

  /**
   * The V4R2 wallet address — the contract this key would deploy, not a hash
   * of the key itself. Non-bounceable (`UQ…`) by default, which is the form a
   * wallet shows for receiving.
   */
  get address(): string {
    return tonAddressFromPublicKey(this.publicKey);
  }

  /** The same account under the bounceable tag (`EQ…`). */
  get bounceableAddress(): string {
    return tonAddressFromPublicKey(this.publicKey, { bounceable: true });
  }

  get name(): string | undefined {
    return this.entry.name ?? this.entry.note ?? undefined;
  }
}

/**
 * Cardano view (CIP-1852): the exported account key supports SOFT public
 * derivation (BIP32-Ed25519), so payment (`0/i`), change (`1/i`) and stake
 * (`2/0`) verification keys derive locally. Bech32 ADDRESS assembly is left
 * to Cardano tooling — `deriveKey` hands you the raw vkeys it needs.
 */
export class CardanoAccountView {
  constructor(
    private readonly entry: RawAccountEntry,
    private readonly resolvedXfp: number,
  ) {}

  get xfp(): string {
    return xfpToHex(this.resolvedXfp);
  }

  get accountPath(): string {
    return formatPath([...this.entry.path]);
  }

  /** The account-level extended public key material. */
  get publicKey(): Uint8Array {
    return requireKey(this.entry, 32);
  }

  get chainCode(): Uint8Array {
    return withChainCode(this.entry);
  }

  /** Signing path for `role/index`, e.g. `pathFor(0, 0)` → `.../0/0`. */
  pathFor(role: number, index: number): string {
    return `${this.accountPath}/${role}/${index}`;
  }

  /**
   * The Shelley base address at receive (or `change:`) `index`.
   *
   * A base address joins the payment key at `<role>/<index>` to the stake key
   * at `2/0`, so it commits to both. The device builds the same 57 bytes.
   */
  deriveAddress(index: number, options?: { change?: boolean }): string {
    return cardanoBaseAddress(
      this.deriveKey(options?.change ? 1 : 0, index),
      this.deriveKey(2, 0),
    );
  }

  /** Soft-derived 32-byte verification key at `role/index` (0 payment, 1 change, 2 stake). */
  deriveKey(role: number, index: number): Uint8Array {
    return cardanoSoftDerivePath(requireKey(this.entry, 32), withChainCode(this.entry), [
      role,
      index,
    ]);
  }
}

/** Sui view: like Solana, each fully-hardened exported entry IS a signer. */
export class SuiAccountView {
  constructor(
    private readonly entry: RawAccountEntry,
    private readonly resolvedXfp: number,
  ) {}

  get xfp(): string {
    return xfpToHex(this.resolvedXfp);
  }

  get path(): string {
    return formatPath([...this.entry.path]);
  }

  get publicKey(): Uint8Array {
    return requireKey(this.entry, 32);
  }

  /** `0x` Sui address: BLAKE2b-256 of `0x00 || publicKey`. */
  get address(): string {
    return suiAddressFromPublicKey(requireKey(this.entry, 32));
  }
}

/**
 * Solana view: Ed25519 has no public child derivation, so the device
 * pre-derives hardened accounts (`m/44'/501'/idx'`) and each entry IS a
 * signer. The public key, base58, IS the address.
 */
/**
 * The three Solana derivation schemes, told apart by path depth:
 * `single` = `m/44'/501'`, `account` = `m/44'/501'/<n>'`,
 * `sub-account` = `m/44'/501'/<n>'/0'`.
 */
export type SolanaScheme = 'single' | 'account' | 'sub-account';

export class SolanaAccountView {
  constructor(
    private readonly entry: RawAccountEntry,
    private readonly resolvedXfp: number,
  ) {}

  get xfp(): string {
    return xfpToHex(this.resolvedXfp);
  }

  get path(): string {
    return formatPath([...this.entry.path]);
  }

  /**
   * Which of the three Solana derivation schemes this entry belongs to.
   *
   * The firmware declares all three under the same `Derivation::Solana` and
   * distinguishes them by PATH DEPTH alone — "Single Account Path"
   * `m/44'/501'`, "Account-based Path" `m/44'/501'/<n>'`, and "Sub-account
   * Path" `m/44'/501'/<n>'/0'`. Without this, three entries all report index
   * 0 with three different addresses, and two entries report each of 1..4.
   */
  get scheme(): SolanaScheme {
    switch (this.entry.path.length) {
      case 2:
        return 'single';
      case 3:
        return 'account';
      default:
        return 'sub-account';
    }
  }

  /**
   * The hardened account index (third path level), 0 for the single-account
   * path which has no such level. Unique only WITHIN a scheme — read it
   * together with [scheme].
   */
  get index(): number {
    return this.entry.path[2]?.index ?? 0;
  }

  get publicKey(): Uint8Array {
    return requireKey(this.entry, 32);
  }

  get address(): string {
    return solanaAddressFromPublicKey(requireKey(this.entry, 32));
  }
}

/**
 * Cosmos view (`m/44'/118'/0'`): one secp256k1 account key, addresses derived
 * at `0/index`. The bech32 PREFIX is the caller's — every zone spends the
 * same key under its own HRP (`cosmos`, `osmo`, `celestia`, ...), so there is
 * no correct default and `deriveAddress` requires one.
 *
 * Ethermint zones (Injective, Evmos, Dymension, ...) are the exception: they
 * sign with `m/44'/60'` keys, so they come back as the `evm` account, not
 * this one.
 */
/** One Cosmos SDK zone, as the firmware's `CosmosCoinInfo` table declares it. */
export interface CosmosChainInfo {
  /** Stable lowercase id, e.g. `osmosis`, `terra-classic`. */
  readonly id: string;
  /** bech32 human-readable part, e.g. `osmo`. */
  readonly hrp: string;
  /** SLIP-44 coin type the zone's account is derived under. */
  readonly slip44: number;
  /**
   * True for Injective, Evmos and Dymension: EVM keys wearing a Cosmos coat.
   * Their account sits at `m/44'/60'` and the bech32 payload is the ETHEREUM
   * address, not the `sha256+ripemd160` hash every other zone uses.
   */
  readonly ethermint?: boolean;
}

/**
 * Every Cosmos zone the device can export a key for, transcribed from
 * `CosmosCoinInfo.cpp`. Twenty-four of them share SLIP-44 118, so the export
 * carries ONE key for all of them and the HRP is what separates the
 * addresses — enumerate this table, never the export's entries, or a caller
 * sees twenty-two identical rows.
 */
export const COSMOS_CHAINS: readonly CosmosChainInfo[] = [
  { id: 'cosmos', hrp: 'cosmos', slip44: 118 },
  { id: 'osmosis', hrp: 'osmo', slip44: 118 },
  { id: 'celestia', hrp: 'celestia', slip44: 118 },
  { id: 'juno', hrp: 'juno', slip44: 118 },
  { id: 'akash', hrp: 'akash', slip44: 118 },
  { id: 'stride', hrp: 'stride', slip44: 118 },
  { id: 'axelar', hrp: 'axelar', slip44: 118 },
  { id: 'neutron', hrp: 'neutron', slip44: 118 },
  { id: 'dydx', hrp: 'dydx', slip44: 118 },
  { id: 'noble', hrp: 'noble', slip44: 118 },
  { id: 'sei', hrp: 'sei', slip44: 118 },
  { id: 'kujira', hrp: 'kujira', slip44: 118 },
  { id: 'stargaze', hrp: 'stars', slip44: 118 },
  { id: 'agoric', hrp: 'agoric', slip44: 118 },
  { id: 'secret', hrp: 'secret', slip44: 529 },
  { id: 'cronos', hrp: 'cro', slip44: 394 },
  { id: 'kava', hrp: 'kava', slip44: 459 },
  { id: 'terra', hrp: 'terra', slip44: 330 },
  { id: 'thorchain', hrp: 'thor', slip44: 931 },
  { id: 'injective', hrp: 'inj', slip44: 60, ethermint: true },
  { id: 'evmos', hrp: 'evmos', slip44: 60, ethermint: true },
  { id: 'dymension', hrp: 'dym', slip44: 60, ethermint: true },
  { id: 'babylon', hrp: 'bbn', slip44: 118 },
  { id: 'neutaro', hrp: 'neutaro', slip44: 118 },
  { id: 'terra-classic', hrp: 'terra', slip44: 330 },
  { id: 'shentu', hrp: 'shentu', slip44: 118 },
  { id: 'persistence', hrp: 'persistence', slip44: 118 },
  { id: 'sommelier', hrp: 'somm', slip44: 118 },
  { id: 'irisnet', hrp: 'iaa', slip44: 118 },
  { id: 'regen', hrp: 'regen', slip44: 118 },
  { id: 'umee', hrp: 'umee', slip44: 118 },
  { id: 'quicksilver', hrp: 'quick', slip44: 118 },
  { id: 'gravity-bridge', hrp: 'gravity', slip44: 118 },
];

const COSMOS_BY_ID = new Map(COSMOS_CHAINS.map((c) => [c.id, c]));

/** Coin types that mean "a Cosmos account", Ethermint's 60 excluded. */
const COSMOS_SLIP44 = new Set(
  COSMOS_CHAINS.filter((c) => !c.ethermint).map((c) => c.slip44),
);

/** Look up a zone by id, or throw with the id that was not found. */
export function cosmosChain(id: string): CosmosChainInfo {
  const found = COSMOS_BY_ID.get(id);
  if (!found) {
    throw new EraSdkError('invalid-props', `unknown Cosmos chain "${id}"`);
  }
  return found;
}

export class CosmosAccountView {
  constructor(
    private readonly entry: RawAccountEntry,
    private readonly resolvedXfp: number,
    /** The zone this view was resolved for, when it was asked for by id. */
    readonly chain?: CosmosChainInfo,
  ) {}

  get xfp(): string {
    return xfpToHex(this.resolvedXfp);
  }

  get accountPath(): string {
    return formatPath([...this.entry.path]);
  }

  /** Signing path for address `index`: `<account>/0/<index>`. */
  pathFor(index: number): string {
    return `${this.accountPath}/0/${index}`;
  }

  /** The compressed secp256k1 key at `0/index` — what a sign request's path names. */
  derivePublicKey(index: number): Uint8Array {
    return derivePublicKey(requireKey(this.entry, 33), withChainCode(this.entry), 0, index);
  }

  /**
   * Bech32 address for this account.
   *
   * Pass `{ chain: 'osmosis' }` to name a zone from the registry — that also
   * picks the right hashing, which matters for Injective, Evmos and Dymension
   * whose payload is the Ethereum address rather than `hash160`. Pass
   * `{ prefix }` for a zone the registry does not carry; that always uses the
   * classic recipe. A view resolved through `cosmos('osmosis')` already knows
   * its zone and needs no options at all.
   */
  deriveAddress(index: number, options?: { prefix?: string; chain?: string }): string {
    const zone = options?.chain ? cosmosChain(options.chain) : this.chain;
    const hrp = options?.prefix ?? zone?.hrp;
    if (!hrp) {
      throw new EraSdkError(
        'invalid-props',
        'name a Cosmos zone: deriveAddress(i, { chain }) or { prefix }',
      );
    }
    const key = this.derivePublicKey(index);
    return options?.prefix === undefined && zone?.ethermint
      ? ethermintAddressFromPublicKey(key, hrp)
      : cosmosAddressFromPublicKey(key, hrp);
  }
}

/**
 * XRP view (`m/44'/144'/0'`). The device signs with ONE key — the address at
 * `0/0` — so `signingPath` names it, and the hex of `derivePublicKey(0)` is
 * what an unsigned transaction's `SigningPubKey` must carry. `pathFor` is
 * there for wallets that scan further addresses of the same account.
 */
export class XrpAccountView {
  constructor(
    private readonly entry: RawAccountEntry,
    private readonly resolvedXfp: number,
  ) {}

  get xfp(): string {
    return xfpToHex(this.resolvedXfp);
  }

  get accountPath(): string {
    return formatPath([...this.entry.path]);
  }

  /** The only path the device signs with: `<account>/0/0`. */
  get signingPath(): string {
    return `${this.accountPath}/0/0`;
  }

  /** Signing path for address `index`: `<account>/0/<index>`. */
  pathFor(index: number): string {
    return `${this.accountPath}/0/${index}`;
  }

  /** The compressed secp256k1 key at `0/index`. */
  derivePublicKey(index: number): Uint8Array {
    return derivePublicKey(requireKey(this.entry, 33), withChainCode(this.entry), 0, index);
  }

  /** Classic `r...` address of the key at `0/index`. */
  deriveAddress(index: number): string {
    return xrpAddressFromPublicKey(this.derivePublicKey(index));
  }
}

function extendedKeyOf(entry: RawAccountEntry, version?: number): string {
  const chainCode = withChainCode(entry);
  const publicKey = requireKey(entry, 33);
  const last = entry.path[entry.path.length - 1]!;
  const args = {
    depth: entry.path.length,
    parentFingerprint: entry.parentFingerprint ?? 0,
    childNumber: last.hardened ? last.index + 0x80000000 : last.index,
    chainCode,
    publicKey,
  };
  return version === undefined
    ? serializeExtendedPublicKey(args)
    : serializeExtendedPublicKey({ ...args, version });
}

/**
 * The linked wallet: everything a software wallet extracts from the device's
 * `crypto-multi-accounts` QR. Parse once, store the source UR string, derive
 * addresses locally — the device is not needed again until signing.
 */
export class EraAccounts {
  private constructor(
    private readonly raw: RawMultiAccounts,
    readonly sourceUr: string | undefined,
  ) {}

  static fromUr(input: Ur | string): EraAccounts {
    const raw = parseMultiAccountsUr(input);
    return new EraAccounts(raw, typeof input === 'string' ? input : input.toString());
  }

  /** Master fingerprint, lowercase 8-hex. */
  get masterFingerprint(): string {
    return xfpToHex(this.raw.masterFingerprint);
  }

  get device(): DeviceInfo {
    return {
      name: this.raw.deviceName ?? undefined,
      id: this.raw.deviceId ?? undefined,
      firmwareVersion: this.raw.deviceVersion ?? undefined,
    };
  }

  get keys(): AccountKey[] {
    return this.raw.entries.map((entry) => ({
      chain: classify(entry.path),
      path: formatPath([...entry.path]),
      xfp: xfpToHex(entry.xfp ?? this.raw.masterFingerprint),
      publicKey: entry.publicKey ?? undefined,
      chainCode: entry.chainCode ?? undefined,
      name: entry.name ?? undefined,
      note: entry.note ?? undefined,
    }));
  }

  /**
   * The xfp a sign request must carry for the account whose path exactly
   * equals `accountPath`. Throws `account-not-found` — never a silent zero.
   */
  xfpFor(accountPath: string): string {
    return xfpToHex(this.resolveXfp(this.entryFor(accountPath)));
  }

  /** Entry xfp, falling back to the wrapper's master fingerprint (Cardano-style path-only origins). */
  private resolveXfp(entry: RawAccountEntry): number {
    return entry.xfp ?? this.raw.masterFingerprint;
  }

  /** The EVM account (standard `m/44'/60'/...` scheme), if the export carries one. */
  evm(): EvmAccountView | undefined {
    const entry =
      this.raw.entries.find(
        (e) => isEvmAccount(e) && (e.note === null || e.note === 'account.standard'),
      ) ?? this.raw.entries.find(isEvmAccount);
    return entry ? new EvmAccountView(entry, this.resolveXfp(entry)) : undefined;
  }

  /**
   * A Bitcoin account view. Defaults to the BIP-84 native-segwit account;
   * pass `purpose: 44` for legacy P2PKH, 49 for nested segwit, 86 for taproot
   * — if the export carries them. Which of those can sign MESSAGES depends on
   * the firmware; see [BtcAccountView].
   *
   * `purpose` is bounded to {44, 49, 84, 86} at RUNTIME, not just by its
   * type: any other value returns `undefined` rather than a view, because an
   * arbitrary purpose has no script type and no address encoding, so a view
   * over it could serve a plausible-looking `xpub()` and refuse only later,
   * at the first address.
   *
   * `testnet` SELECTS an account, it does not re-render one: the match is the
   * export's entry at `m/<purpose>'/<0 | 1>'/...`, and `undefined` comes back
   * when there is none. There is deliberately no fallback to the other
   * network — a mainnet key printed under a testnet HRP is a wrong answer
   * that looks right.
   *
   * ERA firmware exports Bitcoin accounts at coin type 0' only, so for a
   * wallet linked from an ERA device `btc({ testnet: true })` is `undefined`.
   * The option stays because the export format carries coin-type-1' accounts
   * and other wallet profiles populate them.
   */
  btc(options?: { testnet?: boolean; purpose?: BtcPurpose }): BtcAccountView | undefined {
    const purpose = options?.purpose ?? 84;
    if (!BTC_PURPOSES.has(purpose)) return undefined;
    const coinType = options?.testnet ? 1 : 0;
    const entry = this.raw.entries.find((e) => {
      const p0 = e.path[0];
      const p1 = e.path[1];
      return (
        p0 !== undefined &&
        p1 !== undefined &&
        p0.hardened &&
        p1.hardened &&
        p0.index === purpose &&
        p1.index === coinType
      );
    });
    return entry ? new BtcAccountView(entry, purpose, this.resolveXfp(entry)) : undefined;
  }

  tron(): TronAccountView | undefined {
    const entry = this.raw.entries.find((e) => classify(e.path) === 'tron');
    return entry ? new TronAccountView(entry, this.resolveXfp(entry)) : undefined;
  }

  /** The Bitcoin Cash account (`m/44'/145'/0'`), if the export carries one. */
  bch(): BchAccountView | undefined {
    const entry = this.raw.entries.find((e) => classify(e.path) === 'bch');
    return entry ? new BchAccountView(entry, this.resolveXfp(entry)) : undefined;
  }

  /**
   * The Ledger Live EVM accounts — ten fully derived leaves at
   * `m/44'/60'/<n>'/0/0`, in export order. They carry a chain code, which is
   * what tells them apart from the Ethermint keys that share the same path
   * shape and carry none.
   */
  evmLedgerLive(): EvmLedgerAccountView[] {
    return this.raw.entries
      .filter(
        (e) => classify(e.path) === 'evm' && e.path.length === 5 && e.chainCode !== null,
      )
      .map((e) => new EvmLedgerAccountView(e, this.resolveXfp(e), 'ledger-live'));
  }

  /**
   * The Ledger legacy (MEW / MyCrypto) EVM account, whose addresses sit ONE
   * level below it. It shares the standard account's path shape, so it is the
   * depth-3 EVM entry that is NOT the standard one.
   */
  evmLedgerLegacy(): EvmLedgerAccountView | undefined {
    const entry = this.raw.entries.find(
      (e) => isEvmAccount(e) && e.note !== null && e.note !== 'account.standard',
    );
    return entry
      ? new EvmLedgerAccountView(entry, this.resolveXfp(entry), 'ledger-legacy')
      : undefined;
  }

  /**
   * A Litecoin, Dogecoin or Dash account. `purpose` picks the script type
   * where the chain has more than one — Litecoin is exported as BIP-84 by
   * every ERA profile, but a third-party profile may carry 49 or 44 instead,
   * so the default is "whichever the export actually holds", best first.
   */
  utxo(chain: UtxoChain, options?: { purpose?: number }): UtxoAccountView | undefined {
    const wanted = options?.purpose;
    const purposes = wanted === undefined ? UTXO_CHAINS[chain].purposes : [wanted];
    for (const purpose of purposes) {
      const entry = this.raw.entries.find(
        (e) => classify(e.path) === chain && e.path.length === 3 && e.path[0]!.index === purpose,
      );
      if (entry) return new UtxoAccountView(entry, this.resolveXfp(entry), chain);
    }
    return undefined;
  }

  /** The Litecoin account — BIP-84 native segwit unless the export says otherwise. */
  litecoin(options?: { purpose?: number }): UtxoAccountView | undefined {
    return this.utxo('litecoin', options);
  }

  /** The Dogecoin account (`m/44'/3'/0'`, legacy P2PKH — the chain has no segwit). */
  dogecoin(): UtxoAccountView | undefined {
    return this.utxo('dogecoin');
  }

  /** The Dash account (`m/44'/5'/0'`, legacy P2PKH — the chain has no segwit). */
  dash(): UtxoAccountView | undefined {
    return this.utxo('dash');
  }

  /** The TON account (linked via the Tonkeeper-style `crypto-hdkey` export). */
  ton(): TonAccountView | undefined {
    const entry = this.raw.entries.find(
      (e) => classify(e.path) === 'ton' && e.publicKey?.length === 32,
    );
    return entry ? new TonAccountView(entry, this.resolveXfp(entry)) : undefined;
  }

  /** All exported Sui signers (fully hardened SLIP-10 entries). */
  sui(): SuiAccountView[] {
    return this.raw.entries
      .filter((e) => classify(e.path) === 'sui' && e.publicKey?.length === 32)
      .map((e) => new SuiAccountView(e, this.resolveXfp(e)));
  }

  /** The Cardano account (CIP-1852 Icarus export), if the export carries one. */
  cardano(): CardanoAccountView | undefined {
    const entry = this.raw.entries.find(
      (e) => classify(e.path) === 'cardano' && e.publicKey?.length === 32,
    );
    return entry ? new CardanoAccountView(entry, this.resolveXfp(entry)) : undefined;
  }

  /** All pre-derived Solana signers (usually `m/44'/501'/0'..9'`). */
  /**
   * The Solana accounts an export carries — ALREADY DERIVED by the device,
   * one entry per key. Ed25519 hardened paths cannot be walked from a parent
   * public key, so there is nothing to derive here and nothing beyond what the
   * export shipped.
   *
   * Pass `scheme` to take one derivation scheme: the device ships all three,
   * so an unfiltered list holds several entries reporting the same `index`
   * with different addresses.
   */
  solana(options?: { scheme?: SolanaScheme }): SolanaAccountView[] {
    const views = this.raw.entries
      .filter((e) => classify(e.path) === 'solana' && e.publicKey?.length === 32)
      .map((e) => new SolanaAccountView(e, this.resolveXfp(e)));
    return options?.scheme ? views.filter((v) => v.scheme === options.scheme) : views;
  }

  /** The Cosmos account (`m/44'/118'/0'`), if the export carries one. */
  /**
   * A Cosmos account. With no argument this is the shared SLIP-44 118 entry —
   * the one key that serves Cosmos Hub, Osmosis, Celestia and nineteen more.
   * Name a zone (`cosmos('kava')`) to resolve the entry that zone is actually
   * derived under: the non-118 chains have their own coin types, and the
   * Ethermint zones are served by the EVM account.
   */
  cosmos(chainId?: string): CosmosAccountView | undefined {
    if (chainId === undefined) {
      const entry = this.raw.entries.find((e) => classify(e.path) === 'cosmos');
      return entry ? new CosmosAccountView(entry, this.resolveXfp(entry)) : undefined;
    }
    const zone = cosmosChain(chainId);
    const entry = zone.ethermint
      ? this.raw.entries.find(isEvmAccount)
      : this.raw.entries.find(
          (e) =>
            e.path.length === 3 &&
            e.path[0]!.index === 44 &&
            e.path[0]!.hardened &&
            e.path[1]!.index === zone.slip44 &&
            e.path[1]!.hardened,
        );
    return entry ? new CosmosAccountView(entry, this.resolveXfp(entry), zone) : undefined;
  }

  /** Every Cosmos zone this export can actually serve an address for. */
  availableCosmosChains(): readonly CosmosChainInfo[] {
    return COSMOS_CHAINS.filter((c) => this.cosmos(c.id) !== undefined);
  }

  /** The XRP account (`m/44'/144'/0'`), if the export carries one. */
  xrp(): XrpAccountView | undefined {
    const entry = this.raw.entries.find((e) => classify(e.path) === 'xrp');
    return entry ? new XrpAccountView(entry, this.resolveXfp(entry)) : undefined;
  }

  private entryFor(accountPath: string): RawAccountEntry {
    const levels = parsePath(accountPath);
    const entry = this.raw.entries.find((e) => pathEquals(e.path, levels));
    if (!entry) {
      throw new EraSdkError(
        'account-not-found',
        `the linked wallet carries no account at ${accountPath}`,
        { path: accountPath },
      );
    }
    return entry;
  }
}
