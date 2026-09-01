import { EraSdkError } from '../core/errors';
import type { PathLevel } from '../registry/keypath';
import { formatPath, parsePath, pathEquals, xfpToHex } from '../registry/keypath';
import type { RawAccountEntry, RawMultiAccounts } from '../registry/multi-accounts';
import { parseMultiAccountsUr } from '../registry/multi-accounts';
import type { Ur } from '../ur/ur';
import {
  btcNestedSegwitAddressFromPublicKey,
  btcP2pkhAddressFromPublicKey,
  btcP2wpkhAddressFromPublicKey,
  cardanoSoftDerivePath,
  derivePublicKey,
  evmAddressFromPublicKey,
  serializeExtendedPublicKey,
  solanaAddressFromPublicKey,
  tronAddressFromPublicKey,
  ZPUB_VERSION,
} from './derive';

/** Chain family of an exported account, matched by its derivation path — never by the note label. */
export type AccountChain = 'evm' | 'btc' | 'solana' | 'tron' | 'ton' | 'cardano' | 'unknown';

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
  if (
    p1.index === 0 &&
    (p0.index === 84 || p0.index === 49 || p0.index === 44 || p0.index === 86)
  ) {
    return 'btc';
  }
  if (p0.index === 44 && p1.index === 501) return 'solana';
  if (p0.index === 44 && p1.index === 195) return 'tron';
  if (p0.index === 44 && p1.index === 607) return 'ton';
  if (p0.index === 1852 && p1.index === 1815) return 'cardano';
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
 * Bitcoin view over one exported account. The default is the BIP-84
 * native-segwit account; pass `purpose` to reach the other script types the
 * device exports (44 = legacy P2PKH — the kind the device signs MESSAGES for,
 * 49 = nested segwit, 86 = taproot).
 */
export class BtcAccountView {
  constructor(
    private readonly entry: RawAccountEntry,
    private readonly testnet: boolean,
    readonly purpose: BtcPurpose,
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
    }
  }

  xpub(): string {
    return extendedKeyOf(this.entry);
  }

  /** SLIP-132 zpub form of the BIP-84 key, for tools that require it. */
  zpub(): string {
    if (this.purpose !== 84) {
      throw new EraSdkError(
        'invalid-props',
        'zpub is the SLIP-132 form of the BIP-84 account only',
      );
    }
    return extendedKeyOf(this.entry, ZPUB_VERSION);
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
   * pass `purpose: 44` for the legacy P2PKH account (message signing), 49 for
   * nested segwit, 86 for taproot — if the export carries them.
   */
  btc(options?: { testnet?: boolean; purpose?: BtcPurpose }): BtcAccountView | undefined {
    const purpose = options?.purpose ?? 84;
    const entry = this.raw.entries.find(
      (e) => classify(e.path) === 'btc' && e.path[0]?.index === purpose,
    );
    return entry
      ? new BtcAccountView(entry, options?.testnet ?? false, purpose, this.resolveXfp(entry))
      : undefined;
  }

  tron(): TronAccountView | undefined {
    const entry = this.raw.entries.find((e) => classify(e.path) === 'tron');
    return entry ? new TronAccountView(entry, this.resolveXfp(entry)) : undefined;
  }

  /** The TON account (linked via the Tonkeeper-style `crypto-hdkey` export). */
  ton(): TonAccountView | undefined {
    const entry = this.raw.entries.find(
      (e) => classify(e.path) === 'ton' && e.publicKey?.length === 32,
    );
    return entry ? new TonAccountView(entry, this.resolveXfp(entry)) : undefined;
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
