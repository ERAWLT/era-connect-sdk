import { EraSdkError } from '../core/errors';
import type { PathLevel } from '../registry/keypath';
import { formatPath, parsePath, pathEquals, xfpToHex } from '../registry/keypath';
import type { RawAccountEntry, RawMultiAccounts } from '../registry/multi-accounts';
import { parseMultiAccountsUr } from '../registry/multi-accounts';
import type { Ur } from '../ur/ur';
import {
  bchAddressFromPublicKey,
  btcNestedSegwitAddressFromPublicKey,
  btcP2pkhAddressFromPublicKey,
  btcP2wpkhAddressFromPublicKey,
  cardanoSoftDerivePath,
  cosmosAddressFromPublicKey,
  derivePublicKey,
  evmAddressFromPublicKey,
  serializeExtendedPublicKey,
  solanaAddressFromPublicKey,
  suiAddressFromPublicKey,
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
  if (p0.index === 44 && p1.index === 501) return 'solana';
  if (p0.index === 44 && p1.index === 195) return 'tron';
  if (p0.index === 44 && p1.index === 607) return 'ton';
  if (p0.index === 1852 && p1.index === 1815) return 'cardano';
  if (p0.index === 44 && p1.index === 784) return 'sui';
  if (p0.index === 44 && p1.index === 118) return 'cosmos';
  if (p0.index === 44 && p1.index === 144) return 'xrp';
  return 'unknown';
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
        throw new EraSdkError(
          'invalid-props',
          'taproot addresses need the BIP-341 output-key tweak; derive them from xpub() with your Bitcoin library',
        );
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

  /** The hardened account index (third path level). */
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
export class CosmosAccountView {
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

  /** The compressed secp256k1 key at `0/index` — what a sign request's path names. */
  derivePublicKey(index: number): Uint8Array {
    return derivePublicKey(requireKey(this.entry, 33), withChainCode(this.entry), 0, index);
  }

  /** Bech32 address under the zone's own HRP, e.g. `{ prefix: 'osmo' }`. */
  deriveAddress(index: number, options: { prefix: string }): string {
    return cosmosAddressFromPublicKey(this.derivePublicKey(index), options.prefix);
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
        (e) => classify(e.path) === 'evm' && (e.note === null || e.note === 'account.standard'),
      ) ?? this.raw.entries.find((e) => classify(e.path) === 'evm');
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
  solana(): SolanaAccountView[] {
    return this.raw.entries
      .filter((e) => classify(e.path) === 'solana' && e.publicKey?.length === 32)
      .map((e) => new SolanaAccountView(e, this.resolveXfp(e)));
  }

  /** The Cosmos account (`m/44'/118'/0'`), if the export carries one. */
  cosmos(): CosmosAccountView | undefined {
    const entry = this.raw.entries.find((e) => classify(e.path) === 'cosmos');
    return entry ? new CosmosAccountView(entry, this.resolveXfp(entry)) : undefined;
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
