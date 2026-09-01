/**
 * ERA Connect SDK — air-gapped UR/QR linking and signing for the ERA
 * hardware wallet.
 *
 * Headless by design: you render the QR codes and own the camera; the SDK
 * owns every byte of the protocol. No network I/O, no Node built-ins,
 * `Uint8Array` end-to-end.
 */

import type { EraAccounts as EraAccountsType } from './accounts/accounts';
import { EraAccounts } from './accounts/accounts';
import { BtcChain } from './chains/btc';
import { EvmChain } from './chains/evm';
import type { ChainContext, EraConnectConfig } from './chains/shared';
import { resolveContext } from './chains/shared';
import { SolanaChain } from './chains/solana';
import { TonChain } from './chains/ton';
import { TronChain } from './chains/tron';
import type { HardwareCallRequest, KeyDerivationCallProps } from './hardware-call/key-derivation';
import { generateKeyDerivationCall } from './hardware-call/key-derivation';
import { RawModule } from './raw';
import type { UrScannerOptions } from './scan/ur-scanner';
import { UrScanner } from './scan/ur-scanner';
import type { Ur } from './ur/ur';

/** Timing/size constants of the device's own QR pipeline, for progress UI and timeouts. */
export const DeviceProfile = {
  /** What the phone displays to the device: ~200 wire bytes per frame at 8 fps. */
  phoneToDevice: { fragmentBytesOnWire: 200, payloadBytes: 180, frameIntervalMs: 125 },
  /**
   * What the device displays back: 150-byte fragments at 2.5 fps. Receiving
   * is SLOWER than sending — budget scan timeouts accordingly.
   */
  deviceToPhone: { fragmentBytesOnWire: 150, frameIntervalMs: 400 },
} as const;

/** The SDK facade. Cheap to construct; chain modules are created lazily. */
export class EraConnect {
  private readonly context: ChainContext;
  private _evm: EvmChain | undefined;
  private _btc: BtcChain | undefined;
  private _solana: SolanaChain | undefined;
  private _tron: TronChain | undefined;
  private _ton: TonChain | undefined;
  private _raw: RawModule | undefined;

  constructor(config?: EraConnectConfig) {
    this.context = resolveContext(config);
  }

  get evm(): EvmChain {
    this._evm ??= new EvmChain(this.context);
    return this._evm;
  }

  get btc(): BtcChain {
    this._btc ??= new BtcChain(this.context);
    return this._btc;
  }

  get solana(): SolanaChain {
    this._solana ??= new SolanaChain(this.context);
    return this._solana;
  }

  get tron(): TronChain {
    this._tron ??= new TronChain(this.context);
    return this._tron;
  }

  get ton(): TonChain {
    this._ton ??= new TonChain(this.context);
    return this._ton;
  }

  /** Escape hatch for UR types without a dedicated module. */
  get raw(): RawModule {
    this._raw ??= new RawModule(this.context);
    return this._raw;
  }

  /**
   * Linking: parse the device's `crypto-multi-accounts` export (a `Ur` from a
   * scanner, or a single-part `ur:` string).
   */
  parseAccounts(input: Ur | string): EraAccountsType {
    return EraAccounts.fromUr(input);
  }

  /**
   * Pull-model linking: ask the device for SPECIFIC derivations
   * (`qr-hardware-call` 1201). The device answers with a
   * `crypto-multi-accounts` export.
   */
  generateKeyDerivationCall(props: KeyDerivationCallProps): HardwareCallRequest {
    return generateKeyDerivationCall(this.context, props);
  }

  /** A type-agnostic hardened scanner (linking flows, raw flows). */
  scanner(options?: UrScannerOptions): UrScanner {
    return new UrScanner(options);
  }
}

// ---------------------------------------------------------------------------
// Public types & modules
// ---------------------------------------------------------------------------

export type { AccountChain, AccountKey, BtcPurpose, DeviceInfo } from './accounts/accounts';
export {
  BtcAccountView,
  EraAccounts,
  EvmAccountView,
  SolanaAccountView,
  TonAccountView,
  TronAccountView,
} from './accounts/accounts';
export type {
  BtcMessageSignatureResult,
  BtcMessageSignRequestProps,
  BtcPsbtResult,
  BtcPsbtSignRequestProps,
} from './chains/btc';
export { BtcChain } from './chains/btc';
export type { EvmSignatureResult, EvmSignRequestProps } from './chains/evm';
export { EvmChain, EvmDataType } from './chains/evm';
export type {
  ChainContext,
  EraConnectConfig,
  ExpectedReply,
  SignRequest,
} from './chains/shared';
export { DEFAULT_ORIGIN } from './chains/shared';
export type { SolSignatureResult, SolSignRequestProps } from './chains/solana';
export { SolanaChain, SolSignType } from './chains/solana';
export type { TonSignatureResult, TonSignRequestProps } from './chains/ton';
export { TonChain, TonDataType } from './chains/ton';
export type { TronLatestBlock, TronSignatureResult, TronSignRequestProps } from './chains/tron';
export { TronChain } from './chains/tron';
// UTF-8 helpers that work on every Hermes version (TextEncoder does not):
export { utf8Decode, utf8Encode } from './core/bytes';
export type { EraErrorCode } from './core/errors';
export { EraSdkError } from './core/errors';
export type { RandomBytesFn } from './core/rand';
export type {
  DerivationAlgorithm,
  DerivationCurve,
  HardwareCallRequest,
  KeyDerivationCallProps,
  KeyDerivationSchema,
} from './hardware-call/key-derivation';
export type { AnimatedUrOptions } from './qr/animated-ur';
export { AnimatedUr, DEFAULT_FRAGMENT_LENGTH } from './qr/animated-ur';
export { RawModule } from './raw';
export type { ScanFeedResult, ScanRejection, UrScannerOptions } from './scan/ur-scanner';
export { TypedUrScanner, UrScanner } from './scan/ur-scanner';
export { UrLimits } from './ur/limits';
export { Ur } from './ur/ur';
